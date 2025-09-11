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

import com.antmicro.girdl.data.svd.SvdCluster;
import com.antmicro.girdl.data.svd.SvdDevice;
import com.antmicro.girdl.data.svd.SvdField;
import com.antmicro.girdl.data.svd.SvdNamed;
import com.antmicro.girdl.data.svd.SvdPeripheral;
import com.antmicro.girdl.data.svd.SvdRegister;
import com.antmicro.girdl.data.svd.SvdRegisters;
import com.antmicro.girdl.data.xml.XmlParser;
import com.antmicro.girdl.model.Field;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.model.Register;
import com.antmicro.girdl.util.RecursiveTaskMonitor;
import com.antmicro.girdl.util.Reflect;
import com.antmicro.girdl.util.file.Resource;
import ghidra.util.Msg;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import java.util.List;
import java.util.Optional;

public final class SvdImporter implements Importer {

	private static final String ROOT_NODE = "device";
	public static final FilePredicate PREDICATE = FilePredicate.byExtension(SvdImporter::new, ".svd");

	private final Document document;

	public SvdImporter(Resource file) throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);

		this.document = factory.newDocumentBuilder().parse(file.getInputStream());
	}

	private static String trimWithin(String text) {
		return text.trim().replaceAll("\\s+", " ");
	}

	private static String toIdentifier(String text) {
		return trimWithin(text).replaceAll("[^ -~]", "_");
	}

	@Override
	public void load(Context context, RecursiveTaskMonitor monitor) {
		var root = document.getElementsByTagName(ROOT_NODE).item(0);
		SvdDevice device = XmlParser.create().parse(SvdDevice.class, root);

		final String deviceName = device.name;
		final long unitBits = device.addressUnitBits.orElse(8L);
		final long defaultSize = device.size.orElse(0L);

		if (unitBits % 8 != 0) {
			Msg.error(this, "This device uses a non byte aligned addressing, Ghidra will not be able to correctly display it!");
		}

		final List<SvdPeripheral> peripherals = device.peripherals.peripheral;

		peripherals.forEach(peripheral -> {
			SvdPeripheral parent = peripheral.derivedFrom.map(name -> device.peripherals.byName(name)).orElse(null);
			Reflect.resolveOptionals(peripheral, parent);

			parsePeripheral(peripheral, context, device, defaultSize);
		});

		Msg.info(this, "Loaded SVD for device '" + deviceName + "'");
	}

	private void parsePeripheral(SvdPeripheral node, Context context, SvdDevice device, long defaultSize) {

		// only the name is guaranteed to be present by the specification
		final String name = node.name;

		// those fields are optional
		final long base = node.baseAddress.orElse(0L);
		final String group = node.groupName.map(SvdImporter::toIdentifier).orElse(name);
		final String type = node.headerStructName.map(SvdImporter::toIdentifier).orElse(group);
		final String description = node.description.map(SvdImporter::trimWithin).orElse("");
		final String prefix = node.prependToName.map(SvdImporter::toIdentifier).orElse("");
		final String suffix = node.appendToName.map(SvdImporter::toIdentifier).orElse("");

		final Peripheral peripheral = new Peripheral(type);
		peripheral.createBinding(name, base).setDescription(description);

		PeripheralConfig config = new PeripheralConfig(prefix, suffix, defaultSize);

		node.registers.ifPresent(set -> {
			parseRegisterBlockEntry(peripheral, set, device, config);
		});

		// this will add, merge or ignore the peripheral depending on the already loaded data
		context.addPeripheral(peripheral, Optional.ofNullable(name));
	}

	private void parseRegisterBlockEntry(Peripheral peripheral, SvdRegisters set, SvdDevice root, PeripheralConfig config) {
		set.cluster.forEach(cluster -> parseCluster(peripheral, cluster, root, config));
		set.register.forEach(register -> parseRegister(peripheral, register, root, set, config));
	}

	private SvdRegister getRegisterBase(SvdDevice device, SvdRegisters set, String path) {
		if (path == null || path.isEmpty()) {
			return null;
		}

		var parts = path.split("\\.");

		// if we have just one part the path is relative to the enclosing register block
		if (parts.length == 1) {
			if (set.byName(path) instanceof SvdRegister register) {
				return register;
			}

			return null;
		}

		SvdPeripheral peripheral = device.peripherals.byName(parts[0]);

		if (peripheral == null || peripheral.registers.isEmpty()) {
			return null;
		}

		SvdRegisters node = peripheral.registers.orElseThrow();

		for (int i = 1; i < parts.length; i ++) {
			SvdNamed named = node.byName(parts[i]);

			if (named instanceof SvdRegisters registers) {
				node = registers;
			} else if (named instanceof SvdRegister register) {
				return register;
			} else {
				return null;
			}
		}

		return null;
	}

	private void parseCluster(Peripheral peripheral, SvdCluster cluster, SvdDevice root, PeripheralConfig config) {
		cluster.derivedFrom.ifPresent(path -> {
			Msg.error(this, "Register cluster inheritance is not implemented by this plugin!");
		});

		parseRegisterBlockEntry(peripheral, cluster, root, config);
	}

	private void parseRegister(Peripheral peripheral, SvdRegister register, SvdDevice root, SvdRegisters set, PeripheralConfig config) {

		final String path = register.derivedFrom.orElse(null);
		SvdRegister base = getRegisterBase(root, set, path);
		Reflect.resolveOptionals(register, base);

		// those two are required to be present by the specification
		final String name = config.wrapName(toIdentifier(register.name));
		final long offset = register.addressOffset.orElseThrow();

		// those fields are optional
		final String description = register.description.map(SvdImporter::trimWithin).orElse("");
		final int size = register.size.orElse(config.size).intValue();

		peripheral.createRegister(name, offset, size).ifPresent(created -> {
			created.setDescription(description);

			register.fields.ifPresent(fields -> {
				fields.field.forEach(field -> parseField(created, field));
			});
		});
	}

	private void parseField(Register register, SvdField field) {
		SvdField.Range range = field.getBitRange();

		Field created = register.addField(range.start, range.size, field.name);
		field.description.ifPresent(created::setDescription);
	}

	/**
	 * Default values and modifiers that can be passed to registers.
	 */
	private static class PeripheralConfig {
		final String prefix;
		final String suffix;
		final long size;

		PeripheralConfig(String prefix, String suffix, long defaultSize) {
			this.prefix = prefix;
			this.suffix = suffix;
			this.size = defaultSize;
		}

		String wrapName(String name) {
			return prefix + name + suffix;
		}
	}

}
