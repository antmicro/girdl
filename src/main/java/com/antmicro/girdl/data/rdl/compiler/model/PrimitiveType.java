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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class PrimitiveType extends TypeValue {

	private static final Map<String, PrimitiveType> TYPES = new HashMap<>();

	public static final PrimitiveType INTEGER = new PrimitiveType("longint", PrimitiveValue.IntValue::create);
	public static final PrimitiveType BIT = new PrimitiveType("bit", PrimitiveValue.BitValue::create);
	public static final PrimitiveType BOOL = new PrimitiveType("boolean", PrimitiveValue.BoolValue::create);
	public static final PrimitiveType STRING = new PrimitiveType("string", PrimitiveValue.TextValue::create);
	public static final PrimitiveType UNSET = new PrimitiveType("unset", UnsetValue::create);

	private transient final Supplier<Value> supplier;

	private PrimitiveType(String name, Supplier<Value> supplier) {
		super(name);
		this.supplier = supplier;
		TYPES.put(name, this);
	}

	public static TypeValue byName(String name) {
		return TYPES.get(name);
	}

	@Override
	public Value instantiate(Scope scope, Value rhs) {
		return rhs.getType() == this ? rhs : supplier.get();
	}

	static {
		TYPES.put("unsigned longint", INTEGER);
	}

}
