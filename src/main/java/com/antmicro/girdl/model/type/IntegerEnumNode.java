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

import java.util.ArrayList;
import java.util.List;

public class IntegerEnumNode extends TypeNode {

	public final String name;
	public final BaseNode underlying;
	public final List<Enumerator> enumerators = new ArrayList<>();

	private IntegerEnumNode(String name, BaseNode underlying) {
		this.name = name;
		this.underlying = underlying;
	}

	public static IntegerEnumNode of(String name, BaseNode underlying) {
		return new IntegerEnumNode(name, underlying);
	}

	public void addEnumerator(String name, long value) {
		enumerators.add(new Enumerator(name, value));
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptEnum(this);
	}

	@Override
	public int size(int width) {
		return underlying.size(width);
	}

	@Override
	public int hashCode() {
		return 3 * underlying.hashCode() + 11 * enumerators.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) return true;

		if (object instanceof IntegerEnumNode other) {
			return other.underlying.equals(underlying) && other.enumerators.equals(enumerators);
		}

		return false;
	}

	public static class Enumerator {
		public final String name;
		public final long value;

		public Enumerator(String s, long value) {
			name = s;
			this.value = value;
		}
	}

}
