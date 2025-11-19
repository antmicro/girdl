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

public class PointerNode extends TypeNode {

	public TypeNode reference;

	private PointerNode(TypeNode reference) {
		this.reference = reference;
	}

	public static PointerNode of(TypeNode reference) {
		return new PointerNode(reference);
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptPointer(this);
	}

	@Override
	public int size(int width) {
		return width;
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) {
			return true;
		}

		if (object instanceof PointerNode other) {
			return other.reference.equals(reference);
		}

		return false;
	}

	@Override
	public int hashCode() {
		return 11 * reference.hashCode() + 97;
	}

	@Override
	public boolean isPeripheral() {
		return reference.isPeripheral();
	}

}
