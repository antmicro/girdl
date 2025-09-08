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
import com.antmicro.girdl.data.rdl.compiler.ModelNode;

public abstract class Value extends ModelNode {

	public abstract TypeValue getType();

	public Value setLocation(Location location) {
		this.location = location;
		return this;
	}

	public boolean toBool() {
		return toLong() != 0;
	}

	public long toLong() {
		throw new RuntimeException("Unable to convert " + getClass().getSimpleName() + " to long");
	}

	public String toString() {
		return getClass().getSimpleName();
	}

	public static PrimitiveValue.IntValue of(long value) {
		return PrimitiveValue.IntValue.of(value);
	}

	public static PrimitiveValue.BoolValue of(boolean value) {
		return PrimitiveValue.BoolValue.of(value);
	}

	public static PrimitiveValue.TextValue of(String value) {
		return PrimitiveValue.TextValue.of(value);
	}

}
