/*
 * Copyright 2025 Antmicro
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.antmicro.girdl.data;

import com.antmicro.girdl.data.rdl.RenodeRdl;
import com.antmicro.girdl.data.rdl.compiler.Compiler;
import com.antmicro.girdl.data.rdl.compiler.Scope;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentType;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentValue;
import com.antmicro.girdl.data.rdl.compiler.model.ParametricType;
import com.antmicro.girdl.data.rdl.compiler.model.StructuredValue;
import com.antmicro.girdl.data.rdl.compiler.model.TypeValue;
import com.antmicro.girdl.data.rdl.compiler.model.Value;
import com.antmicro.girdl.data.rdl.lexer.Tokenizer;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.data.rdl.parser.ast.RootNode;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.model.Register;
import com.antmicro.girdl.util.DataSource;
import com.antmicro.girdl.util.RecursiveTaskMonitor;
import com.antmicro.girdl.util.file.Resource;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.Objects;

public final class RdlImporter implements Importer {

	public static final FilePredicate PREDICATE = FilePredicate.byExtension(RdlImporter::new, ".rdl");

	private final Resource resource;

	public RdlImporter(Resource file) {
		this.resource = file;
	}

	private void tryLoadingField(Register register, String instanceName, ComponentValue component) {

		long bits = component.getOuterSize();
		long start = component.getStart();
		String desc = component.getField("desc").map(Value::toString).orElse("");

		register.addField(start, bits, instanceName).setDescription(desc);

	}

	private void tryLoadingFields(Register register, ComponentValue component) {

		for (var value : component.values.entrySet()) {
			if (value.getValue() instanceof ComponentValue sub) {
				if (sub.type.kind == ComponentKind.FIELD) {
					tryLoadingField(register, value.getKey(), sub);
				}
			}
		}

	}

	private void tryLoadingRegister(long offset, Peripheral peripheral, String instanceName, ComponentValue component) {

		String desc = component.getField("desc").map(Value::toString).orElse("");
		DataSource name = DataSource.of(component.getField("name").map(Objects::toString).orElse(null), instanceName, component.type.name);
		long width = component.getStride();

		// use our own heuristics
		if (RenodeRdl.GUESSED.equals(desc)) {
			desc = "";
			width = Register.UNKNOWN_SIZE;
		}

		final String description = desc;

		peripheral.createRegister(name.primary().orElseThrow(), offset + component.getStart() / 8, (int) width).ifPresent(register -> {
			name.forEachNonPrimary(register::addAlias);
			register.setDescription(description).setCount((int) component.count);
			tryLoadingFields(register, component);
		});
	}

	private void tryLoadingRegisterSet(long offset, Peripheral peripheral, String ignoredName, ComponentValue component) {

		for (var value : component.values.entrySet()) {
			if (value.getValue() instanceof ComponentValue sub) {
				if (sub.type.kind == ComponentKind.REGISTER) {
					tryLoadingRegister(offset, peripheral, value.getKey(), sub);
				}

				if (sub.type.kind == ComponentKind.REGISTER_FILE) {
					tryLoadingRegisterSet(offset + sub.at, peripheral, sub.type.name, sub);
				}
			}
		}

	}

	private void tryLoadingPeripheral(Context context, String instanceName, ComponentValue component) {

		String name = component.type.name.isBlank() ? instanceName : component.type.name;
		Peripheral peripheral = new Peripheral(name);

		peripheral.addDescription(component.getField("desc").map(Value::toString).orElse(""));

		boolean loaded = false;

		for (var entry : component.values.entrySet()) {
			if (entry.getValue() instanceof ComponentValue sub) {
				if (sub.type.kind == ComponentKind.ADDRESS_MAP) {
					if (loaded) {
						Msg.trace(this, "Found another register set (of instance name: '" + entry.getKey() + "') in peripheral " + name + ", ignoring!");
						peripheral.addDescription("Skipped set '" + name + "'");
					} else {
						tryLoadingRegisterSet(0, peripheral, sub.type.name, sub);
						peripheral.addDescription(sub.getField("desc").map(Value::toString).orElse(""));
					}

					loaded = true;
				}
			}
		}

		// needed if the registers are placed not in an addrmap but directly within the component
		tryLoadingRegisterSet(0, peripheral, "<implicit>", component);

		context.addPeripheral(peripheral, null);
	}

	public void tryLoadAddressMap(Context context, ComponentType component) {

		ComponentValue instance;

		try {
			instance = (ComponentValue) component.create();
		} catch (Exception e) {
			Msg.warn(this, "Failed to instantiate address map: " + component.name + ". The type model printed below:");
			component.dump();
			throw e;
		}

		try {
			tryLoadingPeripheral(context, component.name, instance);
		} catch (Exception e) {
			Msg.warn(this, "Failed to load address map as peripheral: " + component.name + ". The instantiated model printed below:");
			instance.dump();
			throw e;
		}

	}

	@Override
	public void load(Context context, RecursiveTaskMonitor monitor) {

		try {

			Tokenizer tokenizer = new Tokenizer();
			tokenizer.setIncludeResolver((ctx, path) -> ctx.map(res -> res.back().then(path)).orElseThrow());
			context.macros.forEach(macro -> tokenizer.defineMacro(macro.name, macro.value));

			Compiler compiler = new Compiler();
			RootNode root = RootNode.parse(tokenizer.tokenizeFile(resource).preprocess().asTokenStream());

			try {
				compiler.compile(root);
			} catch (Exception e) {
				Msg.error(this, "Failed to compile AST into type model! The abstract syntax tree printed below:");
				root.dump();
				throw e;
			}

			// accept multiple devices per file, in practice Renode only exports one per file
			for (TypeValue node : compiler.getModel().types().values()) {
				if (node instanceof ComponentType component) {
					if (component.kind == ComponentKind.ADDRESS_MAP) {
						tryLoadAddressMap(context, component);
					}
				}

				if (node instanceof ParametricType parametric) {
					if (parametric.getTemplateType() == ComponentKind.ADDRESS_MAP && parametric.isDefaultable()) {
						ComponentType component = parametric.implicitize(Scope.empty(), StructuredValue.empty());
						tryLoadAddressMap(context, component);
					}
				}
			}

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

}
