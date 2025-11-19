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

import com.antmicro.girdl.util.MathHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class StructNode extends TypeNode {

	///  Prefix used to mark inline definitions
	public static final String INLINE_SUFFIX = "_inline";

	private boolean peripheral;
	private boolean anonymous;
	public final String name;
	public List<Entry> fields = new ArrayList<>();
	private int fixedSizeBytes;

	StructNode(String name) {
		this.name = name;
		this.anonymous = false;
	}

	public static StructNode of(String name) {
		return new StructNode(name);
	}

	public static StructNode of() {
		return new StructNode("anonymous").markAnonymous();
	}

	public StructNode addField(TypeNode field, String name, String description) {

		// this is to align the field to a full byte as a struct can also contain bit fields
		if (!fields.isEmpty()) {
			Entry previous = fields.getLast();

			if (previous.isBitField()) {
				long bitsToNextByte = MathHelper.getPadding(getBitSize(0), 8);
				addBitField((int) bitsToNextByte, "align_" + fields.size(), "Byte alignment");
			}
		}

		fields.add(new Entry(name, Objects.requireNonNull(field), description, 0));
		return this;
	}

	public StructNode addBitField(int bits, String name, String description) {
		fields.add(new Entry(name, BaseNode.BITS, description, bits));
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
	public int size(int width) {
		return isFixedSize() ? getFixedSize() : getBitSize(width) / 8;
	}

	protected final int getBitSize(int width) {
		return fields.stream().mapToInt(entry -> entry.getBitSize(width)).sum();
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptStruct(this);
	}

	public StructNode markAnonymous() {
		this.anonymous = true;
		return this;
	}

	public StructNode markPeripheral() {
		this.peripheral = true;
		return this;
	}

	public boolean isAnonymous() {
		return anonymous;
	}

	@Override
	public boolean isPeripheral() {
		return peripheral;
	}

	public boolean isFixedSize() {
		return fixedSizeBytes != 0;
	}

	public int getFixedSize() {
		return fixedSizeBytes;
	}

	public StructNode setFixedSize(int bytes) {
		fixedSizeBytes = bytes;
		return this;
	}

	public static class Entry {
		public final String name;
		public final TypeNode type;
		public final String description;
		public final int bits;

		public Entry(String name, TypeNode type, String description, int bits) {
			this.name = name;
			this.type = type;
			this.description = description;
			this.bits = bits;
		}

		public boolean isBitField() {
			return bits != 0;
		}

		public int getBitSize(int width) {
			return isBitField() ? bits : type.size(width) * 8;
		}
	}

}
