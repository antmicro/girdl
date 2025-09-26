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

@Deprecated
public class BitsNode extends TypeNode {

	public final BaseNode underlying;
	public final List<Entry> fields = new ArrayList<>();

	private BitsNode(BaseNode underlying) {
		this.underlying = underlying;
	}

	public static BitsNode of(BaseNode underlying) {
		return new BitsNode(underlying);
	}

	public BitsNode addField(int bits, String name, String description) {
		fields.add(new Entry(name, description, bits));
		return this;
	}

	@Override
	public int hashCode() {
		return 7 * underlying.hashCode() + 11 * fields.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (object instanceof BitsNode bits) {
			return underlying.equals(bits.underlying) && fields.equals(bits.fields);
		}

		return false;
	}

	public static class Entry {
		public final String name;
		public final String description;
		public final int bits;

		public Entry(String name, String description, int bits) {
			this.name = name;
			this.description = description;
			this.bits = bits;
		}

		@Override
		public String toString() {
			return name + "[" + bits + "]";
		}
	}

	@Override
	public int size(int width) {
		return underlying.size(width);
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptBits(this);
	}

}
