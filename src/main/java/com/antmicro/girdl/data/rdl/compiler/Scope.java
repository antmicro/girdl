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
package com.antmicro.girdl.data.rdl.compiler;

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentType;
import com.antmicro.girdl.data.rdl.compiler.model.StructuredValue;
import com.antmicro.girdl.data.rdl.compiler.model.UnsetValue;
import com.antmicro.girdl.data.rdl.compiler.model.Value;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

public class Scope {

	private static final Scope EMPTY = new Scope();
	private final List<StructuredValue> values = new ArrayList<>();
	private final Map<String, ComponentType.ConstructorEntry> defaults = new HashMap<>();

	public static Scope empty() {
		return EMPTY;
	}

	public Scope copy() {
		Scope scope = new Scope();
		scope.values.addAll(values);
		scope.defaults.putAll(defaults);

		return scope;
	}

	public Scope withProperties(StructuredValue context) {
		if (context.values.isEmpty()) {
			return this;
		}

		Scope scope = copy();
		scope.values.add(context);

		return scope;
	}

	public Scope withDefault(String name, ComponentType.ConstructorEntry entry) {
		Scope scope = copy();
		scope.defaults.put(name, entry);

		return scope;
	}

	public Value get(Location location, String name) {
		for (int i = values.size() - 1; i >= 0; i --) {
			StructuredValue tier = values.get(i);
			Value value = tier.values.get(name);

			if (value != null) {
				if (value == UnsetValue.UNSET) {
					throw ParseError.create(location).setDetail("Symbol '" + name + "' was defined but not provided a value!").build();
				}

				return value;
			}
		}

		throw ParseError.create(location).setDetail("Undefined symbol '" + name + "' referenced!").build();
	}

	public void forEachUnsetDefault(Set<String> set, Consumer<ComponentType.ConstructorEntry> consumer) {
		defaults.entrySet().stream().filter(entry -> !set.contains(entry.getKey())).map(Map.Entry::getValue).forEach(consumer);
	}
}
