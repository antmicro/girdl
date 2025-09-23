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
package com.antmicro.girdl.model;

import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Comparator;

public class Field implements Comparable<Field> {

	public static final Comparator<Field> COMPARATOR = Comparator.comparingLong(Field::getOffset).thenComparing(Field::getName);

	public final long offset;
	public final long size;
	public final String name;
	public String description = "";

	public Field(long offset, long size, String name) {
		this.offset = offset;
		this.size = size;
		this.name = name;
	}

	public Field setDescription(String description) {
		this.description = description;
		return this;
	}

	private String getName() {
		return name;
	}

	private long getOffset() {
		return offset;
	}

	@Override
	public int compareTo(Field other) {
		return COMPARATOR.compare(this, other);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Field other) {
			return other.offset == offset && other.size == size && other.name.equals(name);
		}

		return false;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17, 37).append(offset).append(size).append(name).toHashCode();
	}

	@Override
	public String toString() {
		return name + "[" + offset + ":" + (offset + size) + "]";
	}

}
