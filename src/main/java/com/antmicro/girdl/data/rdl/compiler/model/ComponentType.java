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
package com.antmicro.girdl.data.rdl.compiler.model;

import com.antmicro.girdl.data.rdl.compiler.Scope;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ComponentType extends StructType {

	public final ComponentKind kind;

	/**
	 * Only components are allowed to contain parameters, those are used as extra local
	 * variables during instantiation of the type.
 	 */
	private final StructuredValue parameters;

	/**
	 * Types defined within this component, they have no
	 * effect on the instantiation and are here just for type resolution needs.
 	 */
	private final Map<String, TypeValue> types = new HashMap<>();

	/**
	 * The initializer list constitutes the constructor of a ComponentType,
	 * those functions are invoked when the type is instantiated in order they were defined in.
	 */
	private transient final List<ConstructorEntry> initializers = new ArrayList<>();

	public ComponentType(String name, ComponentKind kind, StructuredValue parameters) {
		super(name);
		this.kind = kind;
		this.parameters = parameters;
	}

	@Override
	public Value instantiate(Scope scope, Value rhs) {
		ComponentValue value = new ComponentValue(this);
		value.values.putAll(((StructuredValue) super.instantiate(scope, UnsetValue.UNSET)).values);

		for (ConstructorEntry init : initializers) {
			init.applyForParameterSet(scope.withProperties(parameters), value);
		}

		return value;
	}

	@Override
	public Map<String, TypeValue> types() {
		return types;
	}

	public void addInitializer(ConstructorEntry callback) {
		initializers.add(callback);
	}

	@FunctionalInterface
	public interface ConstructorEntry {
		void applyForParameterSet(Scope scope, ComponentValue value);
	}

}
