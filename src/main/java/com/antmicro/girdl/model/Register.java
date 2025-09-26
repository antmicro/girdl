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

import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.util.Lazy;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class Register implements Comparable<Register> {

	/**
	 * Setting the register's size to this value will cause
	 * the size to be heuristically deduced based on placement of other registers in the same peripheral.
	 */
	public static final int UNKNOWN_SIZE = 0;
	public static final Comparator<Register> COMPARATOR = Comparator.comparingLong(Register::getOffset).thenComparing(Register::getName);

	public final long offset;

	public final String name;
	public final List<String> aliases = new ArrayList<>();
	private final List<Field> fields = new ArrayList<>();

	private int size = UNKNOWN_SIZE;
	private int count = 1;

	private String description = "";
	private final Lazy<TypeNode> type = new Lazy<>();

	public Register(String name, long offset) {
		this.name = name;
		this.offset = offset;
	}

	public List<Field> getFields() {
		List<Field> sorted = fields.stream().sorted().toList();

		if (sorted.isEmpty()) {
			return List.of();
		}

		// if we have one "Dummy" field then just skip it to not make the output more noisy
		if (sorted.size() == 1 && (sorted.getFirst().size == (size * 8L) || sorted.getFirst().name.equalsIgnoreCase("DUMMY"))) {
			return List.of();
		}

		long index = 0;
		List<Field> filled = new ArrayList<>();

		for (Field field : sorted) {
			if (field.offset > index) {
				long pad = field.offset - index;

				filled.add(new Field(index, pad, "bits_" + pad).setDescription("Padding deduced from field offsets"));
				index += pad;
			}

			filled.add(field);
			index += field.size;
		}

		if (index < size * 8L) {
			long pad = size * 8L - index;
			filled.add(new Field(index, pad, "bits_" + pad).setDescription("Padding deduced from register size"));
		}

		return filled;
	}

	private BaseNode createUnderlyingDataType(int bytes) {

		// empty registers should not exist and are most often caused by RMA failing to deduce register size
		// we try to eliminate some of them ourselves but that is not a silver bullet, e.g. when the last register has no size
		// we can't let the type be empty so just fallback to a byte
		if (bytes == 0) {
			return BaseNode.BYTE;
		}

		return BaseNode.of(bytes);

	}

	private TypeNode createBaseDataType(int bytes) {

		BaseNode underlying = createUnderlyingDataType(bytes);

		if (underlying.isOfIntegralSize()) {

			List<Field> fields = getFields();

			if (fields.isEmpty()) {
				return underlying;
			}

			StructNode bitfield = StructNode.of(name + "bits_" + fields.size());
			bitfield.markAnonymous();
			bitfield.setFixedSize(underlying.size(0));

			for (Field field : fields) {
				bitfield.addBitField((int) field.size, field.name, field.description);
			}

			return bitfield;
		}

		return underlying;
	}

	private TypeNode createFullDataType() {

		final TypeNode base = createBaseDataType(size);

		if (count == 1) {
			return base;
		}

		return ArrayNode.of(base, count);
	}

	public TypeNode getType() {
		return type.getOrCompute(this::createFullDataType);
	}

	public String getDescription() {
		return description + (!aliases.isEmpty() ? "Aka. " + String.join(", ", aliases) : "");
	}

	public int getSize() {
		return size;
	}

	private long getOffset() {
		return offset;
	}

	private String getName() {
		return name;
	}

	public long getEnd() {
		return offset + size;
	}

	public boolean isSizeMissing() {
		return size == 0;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Register other) {
			return other.offset == offset && other.size == size && other.count == count && other.name.equals(name) && other.fields.equals(fields);
		}

		return false;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17, 37).append(offset).append(name).append(size).append(count).append(fields).toHashCode();
	}

	@Override
	public String toString() {
		return name;
	}

	public String toQualifiedString() {
		return "'" + name + "' (" + size + (size == 1 ? " byte" : " bytes") + " at 0x" + Long.toHexString(offset) + ")";
	}

	public Register addAlias(String name) {
		this.aliases.add(name);
		return this;
	}

	public Register setCount(int count) {
		this.type.invalidate();
		this.count = count;
		return this;
	}

	public Register setBytes(int bytes) {
		this.type.invalidate();
		this.size = bytes;
		return this;
	}

	public Register setBits(int bits) {
		return setBytes(bits / 8 + (bits % 8 == 0 ? 0 : 1));
	}

	public Register setDescription(String description) {
		this.description = description;
		return this;
	}

	@Override
	public int compareTo(Register o) {
		return COMPARATOR.compare(this, o);
	}

	public Field addField(long offset, long size, String name) {
		Field field = new Field(offset, size, name);
		fields.add(field);
		return field;
	}

}
