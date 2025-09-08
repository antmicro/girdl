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

/**
 * A Value that contains a pointer to its type,
 * (the specific type may be diffrent for each instance of the value).
 */
public class TypedValue<T extends TypeValue> extends Value {

	public final T type;

	public TypedValue(T type) {
		this.type = type;
	}

	@Override
	public final TypeValue getType() {
		return type;
	}

}
