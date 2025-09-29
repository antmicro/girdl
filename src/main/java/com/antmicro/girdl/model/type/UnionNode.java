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

public class UnionNode extends StructNode {

	private UnionNode(String name) {
		super(name);
	}

	public static UnionNode of(String name) {
		return new UnionNode(name);
	}

	@Override
	public int hashCode() {
		return 3 * super.hashCode() + 499;
	}

	@Override
	public boolean equals(Object object) {
		if (this == object) {
			return true;
		}

		if (object instanceof UnionNode) {
			return super.equals(object);
		}

		return false;
	}

	@Override
	public int size(int width) {
		return fields.stream().mapToInt(entry -> entry.type.size(width)).max().orElse(0);
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptUnion(this);
	}

}
