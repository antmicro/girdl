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

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.compiler.Param;
import com.antmicro.girdl.data.rdl.compiler.Scope;
import com.antmicro.girdl.util.Lookup;

public class StructType extends CompositeType {

	/**
	 * Type for anonymous struct literals.
	 */
	public static final StructType ANONYMOUS = new StructType("<anonymous>");

	public final Lookup<Param> fields = new Lookup<>();

	public StructType(String name) {
		super(name);
	}

	/**
	 * Inherit all fields from the super type,
	 * they will be placed BEFORE all the current fields.
	 */
	public void inherit(TypeValue superType) {

		if (superType instanceof StructType parent) {
			fields.addAll(parent.fields);
			return;
		}

		throw new RuntimeException("Structs can only inherit from other structs!");
	}

	@Override
	public Value instantiate(Scope scope, Value rhs) {
		StructuredValue value = new StructuredValue(this);

		// if we were given a structured value in instantiation some fields may have been provided
		// if that is the case they should have precedence over default values
		if (rhs instanceof StructuredValue struct) {
			for (var entry : struct.values.entrySet()) {

				final Param field = fields.getByName(entry.getKey());

				if (field == null) {
					throw new RuntimeException("Trying to set the value of non-existent field '" + entry.getKey() + "' in instantiation of struct " + name);
				}

				value.values.put(entry.getKey(), field.type.instantiate(scope, entry.getValue()));
			}

		} else if (rhs != UnsetValue.UNSET) {
			throw new RuntimeException("Invalid implicit type conversion from " + rhs.getType().name + " to " + name);
		}

		for (Param field : fields.values()) {
			if (!value.values.containsKey(field.name)) {
				value.values.put(field.name, field.getDefault(scope).orElseThrow(() -> ParseError.create(field.location).setDetail("Field '" + field.name + "' is undefined!").build()));
			}
		}

		return value;
	}

	public void addField(String name, TypeValue type, Param.Init provider, Location location) {
		fields.add(name, new Param(type, name, provider, location));
	}

}
