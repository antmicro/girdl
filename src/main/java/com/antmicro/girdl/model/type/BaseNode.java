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
package com.antmicro.girdl.model.type;

public class BaseNode extends TypeNode {

	public static final BaseNode BYTE = of(1);
	public static final BaseNode VOID = of(0, "void");
	public static final TypeNode BITS = of(8, "bits");

	public final int bytes;
	public final String name;

	public BaseNode(int bytes, String name) {
		this.bytes = bytes;
		this.name = name;
	}

	public static BaseNode of(int bytes) {
		return new BaseNode(bytes, "uint" + (bytes * 8) + "_t");
	}

	public static BaseNode of(int bytes, String name) {
		return new BaseNode(bytes, name);
	}

	public boolean isVoid() {
		return bytes == 0;
	}

	@Override
	public int hashCode() {
		return bytes + 7 * name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof BaseNode base) {
			return base.bytes == bytes && base.name.equals(name);
		}

		return false;
	}

	@Override
	public int size(int width) {
		return bytes;
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptBase(this);
	}

	public boolean isOfIntegralSize() {
		return bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8;
	}

}
