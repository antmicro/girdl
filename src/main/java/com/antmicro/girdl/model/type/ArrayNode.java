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

public class ArrayNode extends TypeNode {

	public final int length;
	public final TypeNode element;

	public ArrayNode(int length, TypeNode element) {
		this.length = length;
		this.element = element;
	}

	public static ArrayNode of(TypeNode element, int count) {
		return new ArrayNode(count, element);
	}

	@Override
	public int hashCode() {
		return length + 3 * element.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (object instanceof ArrayNode array) {
			return (length == array.length) && element.equals(array.element);
		}

		return false;
	}

	@Override
	public int size(int width) {
		return element.size(width) * length;
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptArray(this);
	}

}
