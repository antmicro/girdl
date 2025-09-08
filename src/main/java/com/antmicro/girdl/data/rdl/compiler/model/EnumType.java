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

/**
 * TODO enums don't work inside parametric types, don't handle scope correctly etc.
 */
public class EnumType extends TypeValue {

	private final Lookup<Param> enumerations = new Lookup<>();

	public EnumType(String name) {
		super(name);
	}

	@Override
	public Value instantiate(Scope scope, Value rhs) {

		// the default value of the enum is the first defined enumeration
		if (rhs == UnsetValue.UNSET) {
			return enumerations.values().getFirst().getDefault(scope).orElseThrow(() -> ParseError.create(location).setDetail("Enum '" + name + "' has no entries!").build());
		}

		throw new RuntimeException("Invalid implicit type conversion from " + rhs + " to enum " + name);
	}

	public Value getEnumerationByName(String id) {
		// maybe we should reference the use site here?
		return enumerations.getByName(id).getDefault(Scope.empty()).orElseThrow(() -> ParseError.create(location).setDetail("No enumeration '" + id + "' defined in enum " + name).build());
	}

	public void addEnumeration(Location location, String name, Param.Init init) {
		enumerations.add(name, new Param(PrimitiveType.INTEGER, name, init, location));
	}

}
