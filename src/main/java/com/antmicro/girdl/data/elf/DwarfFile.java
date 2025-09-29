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
package com.antmicro.girdl.data.elf;

import com.antmicro.girdl.data.bin.DataWriter;
import com.antmicro.girdl.data.bin.SegmentedBuffer;
import com.antmicro.girdl.data.elf.enums.DwarfAttr;
import com.antmicro.girdl.data.elf.enums.DwarfEncoding;
import com.antmicro.girdl.data.elf.enums.DwarfForm;
import com.antmicro.girdl.data.elf.enums.DwarfOp;
import com.antmicro.girdl.data.elf.enums.DwarfTag;
import com.antmicro.girdl.data.elf.enums.DwarfUnit;
import com.antmicro.girdl.data.elf.enums.ElfSectionFlag;
import com.antmicro.girdl.data.elf.enums.ElfSectionType;
import com.antmicro.girdl.data.elf.enums.ElfSymbolFlag;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.BitsNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PassTypeAdapter;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.model.type.TypedefNode;
import com.antmicro.girdl.model.type.UnionNode;
import com.antmicro.girdl.util.Lazy;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

public class DwarfFile extends ElfFile {

	public static final int DWARF_VERSION = 5;

	private int index = 1;

	private final SegmentedBuffer info;
	private final SegmentedBuffer dies;
	private final SegmentedBuffer abbrev;
	private final SegmentedBuffer bss;

	private final Map<TypeNode, DataWriter> types = new HashMap<>();
	private final int bits;
	private final int bytes;

	private final Template unit;
	private final Template structure;
	private final Template anonymous;
	private final Template union;
	private final Template member;
	private final Template bitfield;
	private final Template primitive;
	private final Template array;
	private final Template subrange;
	private final Template variable;
	private final Template typedef;
	private final Template pointer;
	private final Template enumeration;
	private final Template enumerator;
	private final Template procedure;
	private final Template function;
	private final Template parameter;

	// type used for bitfield fields
	private final Lazy<DataWriter> integral = new Lazy<>();

	public DwarfFile(File file, /* ElfMachine */ int machine, int bits) {
		super(file, machine);

		this.bits = bits;
		this.bytes = bits / 8;
		if (((bits & 7) != 0) || (bits <= 0)) throw new RuntimeException("Integer " + bits + " is not a valid address bit width!");

		// we may want to place string into the debug_str section, this is how we would define that section correctly:
		// createSection(".debug_str", ElfSectionType.PROGBITS, ElfSectionFlag.MERGE | ElfSectionFlag.STRINGS, 1, 0);

		bss = createSection(".bss", ElfSectionType.NOBITS, ElfSectionFlag.WRITE | ElfSectionFlag.ALLOC, 32, 0, null);
		info = createSection(".debug_info", ElfSectionType.PROGBITS, ElfSectionFlag.NONE, 1, 0, null);
		SegmentedBuffer debugAbbrev = createSection(".debug_abbrev", ElfSectionType.PROGBITS, ElfSectionFlag.NONE, 1, 0, null);

		// split into separate buffer to ensue the segment is null-terminated
		abbrev = debugAbbrev.putSegment().setName("Abbrevs");
		debugAbbrev.putByte(0);

		// compilation unit header
		info.putInt(() -> info.size() - 4); // length (excluding the length field itself)
		info.putShort(DWARF_VERSION);
		info.putByte(DwarfUnit.COMPILE);
		info.putByte(bytes); // pointer size on the target architecture
		info.putInt(0); // abbrev offset

		dies = info.putSegment().setName("DIEs");
		info.putByte(0);

		unit = createTemplate(DwarfTag.COMPILE_UNIT, true)
				.add(DwarfAttr.PRODUCER, DwarfForm.STRING)
				.add(DwarfAttr.LANGUAGE, DwarfForm.DATA1)
				.add(DwarfAttr.NAME, DwarfForm.STRING);

		structure = createTemplate(DwarfTag.STRUCTURE_TYPE, true)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA2);

		anonymous = createTemplate(DwarfTag.STRUCTURE_TYPE, true)
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA2);

		union = createTemplate(DwarfTag.UNION_TYPE, true)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA2);

		member = createTemplate(DwarfTag.MEMBER, false)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.DATA_MEMBER_LOCATION, DwarfForm.DATA2)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		bitfield = createTemplate(DwarfTag.MEMBER, false)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.DATA_BIT_OFFSET, DwarfForm.DATA2)
				.add(DwarfAttr.BIT_SIZE, DwarfForm.DATA2)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		primitive = createTemplate(DwarfTag.BASE_TYPE, false)
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA1)
				.add(DwarfAttr.ENCODING, DwarfForm.DATA1)
				.add(DwarfAttr.NAME, DwarfForm.STRING);

		variable = createTemplate(DwarfTag.VARIABLE, false)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.TYPE, DwarfForm.REF4)
				.add(DwarfAttr.LOCATION, DwarfForm.EXPRLOC);

		array = createTemplate(DwarfTag.ARRAY_TYPE, true)
				.add(DwarfAttr.TYPE, DwarfForm.REF4)
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA2);

		subrange = createTemplate(DwarfTag.SUBRANGE_TYPE, false)
				.add(DwarfAttr.UPPER_BOUND, DwarfForm.DATA2);

		typedef = createTemplate(DwarfTag.TYPEDEF, false)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		pointer = createTemplate(DwarfTag.POINTER_TYPE, false)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		enumeration = createTemplate(DwarfTag.ENUMERATION_TYPE, true)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		enumerator = createTemplate(DwarfTag.ENUMERATOR, false)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.CONST_VALUE, DwarfForm.DATA8);

		procedure = createTemplate(DwarfTag.SUBPROGRAM, true)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.LOW_PC, DwarfForm.DATA8)
				.add(DwarfAttr.HIGH_PC, DwarfForm.DATA8);

		function = createTemplate(DwarfTag.SUBPROGRAM, true)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.LOW_PC, DwarfForm.DATA8)
				.add(DwarfAttr.HIGH_PC, DwarfForm.DATA8)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		parameter = createTemplate(DwarfTag.FORMAL_PARAMETER, false)
				.add(DwarfAttr.NAME, DwarfForm.STRING)
				.add(DwarfAttr.TYPE, DwarfForm.REF4);

		unit.create(dies)
				.putString("girdl")
				.putByte(1)
				.putString("peripherals");

	}

	public void createPeripheral(Peripheral peripheral) {
		TypeNode node = peripheral.getType(PassTypeAdapter.INSTANCE);
		createType(node);

		peripheral.bindings.forEach(binding -> {
			createVariable(node, binding.name, binding.address);
		});
	}

	public void createVariable(TypeNode node, String name, long address) {
		DataWriter type = createType(node);

		SegmentedBuffer buffer = variable.create(dies);
		buffer.putString(name).putInt(() -> type.offset() - info.offset());

		createSymbol(name, address, node.size(bytes), ElfSymbolFlag.GLOBAL | ElfSymbolFlag.OBJECT, bss);

		SegmentedBuffer head = buffer.putSegment();
		SegmentedBuffer body = buffer.putSegment();

		body.putByte(DwarfOp.ADDR).putDynamic(bits, address);
		head.putUnsignedLeb128(body.size()); // not linked!
	}

	public DataWriter createType(TypeNode type) {

		if (type == null) {
			return null;
		}

		DataWriter writer = types.get(type);

		if (writer != null) {
			return writer;
		}

		return switch (type) {
			case BaseNode node -> fromBaseNode(node);
			case ArrayNode node -> fromArrayNode(node);
			case BitsNode node -> fromBitsNode(node);
			case UnionNode node -> fromStructNode(node, union);
			case StructNode node -> fromStructNode(node, structure);
			case TypedefNode node -> fromTypedefNode(node);
			case PointerNode node -> fromPointerNode(node);
			case IntegerEnumNode node -> fromIntegerEnumNode(node);
			case FunctionNode node -> fromFunctionNode(node);

			default -> throw new RuntimeException("Unknown type node " + type + "!");
		};
	}

	private DataWriter fromBaseNode(BaseNode type) {
		DataWriter buffer = primitive.create(dies);
		buffer.putByte(type.bytes);
		buffer.putByte(DwarfEncoding.UNSIGNED);
		buffer.putString(type.toString());

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromArrayNode(ArrayNode type) {
		DataWriter element = createType(type.element);

		SegmentedBuffer buffer = array.create(dies);
		buffer.putInt(() -> element.offset() - info.offset());
		buffer.putShort(type.size(bytes));

		subrange.create(buffer).putShort(type.length);

		buffer.putByte(0);

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromBitsNode(BitsNode type) {
		int bytes = type.underlying.bytes;

		DataWriter field = integral.getOrCompute(() -> createType(BaseNode.of(8)));

		SegmentedBuffer buffer = anonymous.create(dies);
		buffer.putShort(bytes);

		int offset = 0;

		for (BitsNode.Entry entry : type.fields) {

			bitfield.create(buffer)
					.putString(entry.name)
					.putShort(offset)
					.putShort(entry.bits)
					.putInt(() -> field.offset() - info.offset());

			offset += entry.bits;

		}

		final int remaining = bytes * 8 - offset;

		// make sure our field isn't too small
		if (remaining > 0) {

			bitfield.create(buffer)
					.putString("unspecified")
					.putShort(offset)
					.putShort(remaining)
					.putInt(() -> field.offset() - info.offset());

		}

		buffer.putByte(0);

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromStructNode(StructNode type, Template template) {

		for (StructNode.Entry entry : type.fields) {
			createType(entry.type);
		}

		SegmentedBuffer buffer = template.create(dies);
		buffer.putString(type.name);
		buffer.putShort(type.size(bytes));

		int offset = 0;

		for (StructNode.Entry entry : type.fields) {
			DataWriter typeBuffer = types.get(entry.type);

			if (typeBuffer == null) {
				throw new RuntimeException("Undefined type in tree refed by name '" + entry.name + "' (" + entry.type + "), is the type model not a tree?");
			}

			member.create(buffer)
					.putString(entry.name)
					.putShort(offset)
					.putInt(() -> typeBuffer.offset() - info.offset());

			offset += entry.type.size(bytes);
		}

		buffer.putByte(0);

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromTypedefNode(TypedefNode type) {

		DataWriter underlying = createType(type.underlying);

		SegmentedBuffer buffer = typedef.create(dies);
		buffer.putString(type.name);
		buffer.putInt(() -> underlying.offset() - info.offset());

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromPointerNode(PointerNode type) {

		DataWriter underlying = createType(type.reference);

		SegmentedBuffer buffer = pointer.create(dies);
		buffer.putInt(() -> underlying.offset() - info.offset());

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromIntegerEnumNode(IntegerEnumNode type) {
		DataWriter underlying = createType(type.underlying);

		SegmentedBuffer buffer = enumeration.create(dies);
		buffer.putString(type.name);
		buffer.putInt(() -> underlying.offset() - info.offset());

		for (IntegerEnumNode.Enumerator entry : type.enumerators) {

			enumerator.create(buffer)
					.putString(entry.name)
					.putLong(entry.value);

		}

		buffer.putByte(0);

		types.put(type, buffer);
		return buffer;
	}

	private DataWriter fromFunctionNode(FunctionNode type) {
		DataWriter returnType = createType(type.result);

		for (FunctionNode.Parameter entry : type.parameters) {
			createType(entry.type);
		}

		SegmentedBuffer buffer = (returnType == null ? procedure : function).create(dies);
		buffer.putString(type.name);
		buffer.putLong(type.low);
		buffer.putLong(type.high);

		if (returnType != null) {
			buffer.putInt(() -> returnType.offset() - info.offset());
		}

		for (FunctionNode.Parameter entry : type.parameters) {

			DataWriter parameterBuffer = createType(entry.type);

			parameter.create(buffer)
					.putString(entry.name)
					.putInt(() -> parameterBuffer.offset() - info.offset());

		}

		buffer.putByte(0);

		types.put(type, buffer);
		return buffer;
	}

	protected Template createTemplate(/* DwarfTag */ int tag, boolean hasChildren) {
		SegmentedBuffer buffer = abbrev.putSegment().setName("Abbreviation #" + index);
		abbrev.putShort(0); // terminate this abbreviation

		final int type = index;
		index ++;

		buffer.putUnsignedLeb128(type);
		buffer.putByte(tag);
		buffer.putBool(hasChildren);

		return new Template(buffer, type);
	}

	protected static class Template {

		final SegmentedBuffer buffer;
		final int index;

		Template(SegmentedBuffer buffer, int index) {
			this.buffer = buffer;
			this.index = index;
		}

		Template add(/* DwarfAttr */ int attribute, /* DwarfForm */ int format) {
			buffer.putByte(attribute);
			buffer.putByte(format);

			return this;
		}

		SegmentedBuffer create(SegmentedBuffer parent) {
			SegmentedBuffer buffer = parent.putSegment().setName("Instance #" + index);
			buffer.putUnsignedLeb128(index);
			return buffer;
		}

	}

}
