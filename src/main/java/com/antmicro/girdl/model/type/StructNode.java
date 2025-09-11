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

public class StructNode extends TypeNode {

	public final String name;
	public List<Entry> fields = new ArrayList<>();

	private StructNode(String name) {
		this.name = name;
	}

	public static StructNode of(String name) {
		return new StructNode(name);
	}

	public StructNode addField(TypeNode field, String name, String description) {
		fields.add(new Entry(name, field, description));
		return this;
	}

	@Override
	public int hashCode() {
		return 7 * name.hashCode() + 11 * fields.hashCode();
	}

	@Override
	public boolean equals(Object object) {
		if (object instanceof StructNode bits) {
			return name.equals(bits.name) && fields.equals(bits.fields);
		}

		return false;
	}

	@Override
	public int size() {
		return fields.stream().mapToInt(entry -> entry.type.size()).sum();
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptStruct(this);
	}

	public static class Entry {
		public final String name;
		public final TypeNode type;
		public final String description;

		public Entry(String name, TypeNode type, String description) {
			this.name = name;
			this.type = type;
			this.description = description;
		}
	}

}
