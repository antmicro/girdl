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
import com.antmicro.girdl.data.elf.storage.AddressStorage;
import com.antmicro.girdl.data.elf.storage.ConstStorage;
import com.antmicro.girdl.data.elf.storage.DynamicStorage;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PassTypeAdapter;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.model.type.TypedefNode;
import com.antmicro.girdl.model.type.UnionNode;
import com.antmicro.girdl.util.Lazy;
import com.antmicro.girdl.util.Reflect;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class DwarfFile extends ElfFile {

	public static final int DWARF_VERSION = 5;

	private final Lazy<LineProgrammer> lines = new Lazy<>();
	private final Lazy<LocationProgrammer> locations = new Lazy<>();

	private int id = 1;
	private final SegmentedBuffer info;
	private final SegmentedBuffer dies;
	private final SegmentedBuffer abbrev;
	private final SegmentedBuffer bss;

	private final Map<TypeNode, DataWriter> types = new HashMap<>();
	private final int bits;
	private final int bytes;

	private final HashMap<DwarfAbbreviation, Integer> abbreviations = new HashMap<>();
	private final Set<Builder> holders = new HashSet<>();

	class Builder {

		private final SegmentedBuffer head;
		private final SegmentedBuffer body;
		private final int tag;
		private boolean children = false;
		private final List<DwarfAttribute> attributes = new ArrayList<>();

		private Builder(SegmentedBuffer buffer, /* DwarfTag */ int tag) {

			final String name = "Instance " + Reflect.constValueName(DwarfTag.class, tag);
			head = buffer.putSegment().setName(name + " head");
			body = buffer.putSegment().setName(name + " body");

			this.tag = tag;

			holders.add(this);
		}

		public Builder withChildren() {
			this.children = true;
			return this;
		}

		public Builder add(/* DwarfAttr */ int attribute, /* DwarfForm */ int format, Consumer<SegmentedBuffer> writer) {

			try {
				// throwing in writer aborts the creation of its attribute
				writer.accept(body);
				attributes.add(new DwarfAttribute(attribute, format));
			} catch (RuntimeException e) {
				return this;
			}

			return this;
		}

		public Builder add(/* DwarfAttr */ int attribute, /* DwarfForm */ int format, String string) {
			return add(attribute, format, buffer -> buffer.putString(string));
		}

		/**
		 * Create an abbreviation matching the specified layout
		 * if it is missing or fetches the ID from cache otherwise.
		 */
		private int getOrCreateIdentifier() {
			final DwarfAbbreviation abbreviation = new DwarfAbbreviation(tag, children, Collections.unmodifiableList(attributes));
			return abbreviations.computeIfAbsent(abbreviation, template -> template.write(abbrev, id ++));
		}

		public SegmentedBuffer done() {
			head.putUnsignedLeb128(getOrCreateIdentifier());
			holders.remove(this);
			return head;
		}
	}

	private Builder create(/* DwarfTag */ int tag, SegmentedBuffer dies) {
		return new Builder(dies, tag);
	}

	public DwarfFile(File file, /* ElfMachine */ int machine, int bits) {
		super(file, machine);

		File parent = file.getParentFile();
		String directory = parent == null ? new File("./").getAbsolutePath() : parent.getAbsolutePath();

		this.bits = bits;
		this.bytes = bits / 8;
		if (((bits & 7) != 0) || (bits <= 0)) throw new RuntimeException("Integer " + bits + " is not a valid address bit width!");

		// we may want to place string into the debug_str section, this is how we would define that section correctly:
		// createSection(".debug_str", ElfSectionType.PROGBITS, ElfSectionFlag.MERGE | ElfSectionFlag.STRINGS, 1, 0);

		bss = createSection(".bss", ElfSectionType.NOBITS, ElfSectionFlag.WRITE | ElfSectionFlag.ALLOC, 0, 0, null);
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

		create(DwarfTag.COMPILE_UNIT, dies).withChildren()
				.add(DwarfAttr.PRODUCER, DwarfForm.STRING, "girdl")
				.add(DwarfAttr.LANGUAGE, DwarfForm.DATA1, buffer -> buffer.putByte(1))
				.add(DwarfAttr.NAME, DwarfForm.STRING, file.getName() + ".c")
				.add(DwarfAttr.COMP_DIR, DwarfForm.STRING, directory)
				.add(DwarfAttr.STMT_LIST, DwarfForm.DATA8, buffer -> buffer.putLong(0))
				.done();

	}

	/**
	 * Get, or create if not yet used, an object for programming source information into DWARF.
	 * Mapping of addresses to a source location in DWARF is handled using a pseudo virtual machine, where
	 * opcodes are defined for specific operations. That program is then interpreted to generate the final mapping table.
	 * It works like this to save space and allow for easy extensibility.
	 */
	public LineProgrammer createLineProgram() {
		return lines.get(() -> new LineProgrammer(createSection(".debug_line", ElfSectionType.PROGBITS, ElfSectionFlag.NONE, 1, 0, null), getAddressWidth()));
	}

	/**
	 * Get, or create if not yet used, an object for programming variable location maps into DWARF.
	 * Each variable can either have a single static storage (register, stack location, etc.) or be
	 * linked to a location list (one of the lists from .debug_loclists section), that list then
	 * defined the storage in relation to the program counter, so that the reality of compiler optimization can be expressed.
	 */
	public LocationProgrammer createLocationLists() {
		return locations.get(() -> new LocationProgrammer(createSection(".debug_loclists", ElfSectionType.PROGBITS, ElfSectionFlag.NONE, 1, 0, null), getAddressWidth()));
	}

	public void createPeripheral(Peripheral peripheral, long offset) {
		TypeNode node = peripheral.getType(PassTypeAdapter.INSTANCE);
		createType(node, dies);

		peripheral.bindings.forEach(binding -> {
			createGlobalVariable(node, binding.name, Storage.ofAddress(binding.address + offset));
		});
	}

	public void createGlobalVariable(TypeNode node, String name, Storage storage) {
		DataWriter type = createType(node, dies);

		if (storage instanceof AddressStorage where) {
			createSymbol(name, where.address, node.size(bytes), ElfSymbolFlag.GLOBAL | ElfSymbolFlag.OBJECT, bss);
		}

		Builder builder = create(DwarfTag.VARIABLE, dies)
				.add(DwarfAttr.NAME, DwarfForm.STRING, name)
				.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> type.from(info)));

		if (storage.hasLocation()) {
			builder.add(DwarfAttr.LOCATION, DwarfForm.EXPRLOC, DwarfExpression.from(expr -> {

				if (storage instanceof AddressStorage where) {
					expr.putByte(DwarfOp.ADDR).putDynamic(bits, where.address);
					return;
				}

				throw new RuntimeException("Unsupported global variable storage!");
			}));
		}

		if (storage instanceof ConstStorage where) {
			builder.add(DwarfAttr.CONST_VALUE, DwarfForm.DATA8, buffer -> buffer.putLong(where.value));
		}

		builder.done();
	}

	public void createType(TypeNode type) {
		createType(type, dies);
	}

	private DataWriter createType(TypeNode type, SegmentedBuffer dies) {

		if (type == null) {
			return null;
		}

		DataWriter writer = types.get(type);

		if (writer != null) {
			return writer;
		}

		return switch (type) {
			case BaseNode node -> fromBaseNode(node, dies);
			case ArrayNode node -> fromArrayNode(node, dies);
			case UnionNode node -> fromStructNode(node, DwarfTag.UNION_TYPE, dies);
			case StructNode node -> fromStructNode(node, DwarfTag.STRUCTURE_TYPE, dies);
			case TypedefNode node -> fromTypedefNode(node, dies);
			case PointerNode node -> fromPointerNode(node, dies);
			case IntegerEnumNode node -> fromIntegerEnumNode(node, dies);
			case FunctionNode node -> fromFunctionNode(node, dies);

			default -> throw new RuntimeException("Unknown type node " + type + "!");
		};
	}

	private Builder beginType(TypeNode type, /* DwarfTag */ int tag, SegmentedBuffer dies) {
		Builder builder = create(tag, dies);
		types.put(type, builder.head);

		return builder;
	}

	private DataWriter fromBaseNode(BaseNode type, SegmentedBuffer dies) {
		return beginType(type, DwarfTag.BASE_TYPE, dies)
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA1, buffer -> buffer.putByte(type.bytes))
				.add(DwarfAttr.ENCODING, DwarfForm.DATA1, buffer -> buffer.putByte(DwarfEncoding.UNSIGNED))
				.add(DwarfAttr.NAME, DwarfForm.STRING, type.toString())
				.done();
	}

	private DataWriter fromArrayNode(ArrayNode type, SegmentedBuffer dies) {
		final SegmentedBuffer before = dies.putSegment();
		final DataWriter element = createType(type.element, before);

		SegmentedBuffer array = beginType(type, DwarfTag.ARRAY_TYPE, dies).withChildren()
				.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> element.from(info)))
				.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA2, buffer -> buffer.putShort(type.size(bytes)))
				.done();

		create(DwarfTag.SUBRANGE_TYPE, dies)
				.add(DwarfAttr.UPPER_BOUND, DwarfForm.DATA2, buffer -> buffer.putShort(type.length))
				.done();

		dies.putByte(0);
		return array;
	}

	private DataWriter fromStructNode(StructNode type, /* DwarfTag */ int tag, SegmentedBuffer dies) {
		SegmentedBuffer before = dies.putSegment();
		Builder builder = beginType(type, tag, dies).withChildren();

		for (StructNode.Entry entry : type.fields) {
			createType(entry.type, before);
		}

		// the base type will ony be directly needed if we need to add padding
		// and padding will only ever be added if the structure is of fixed size
		if (type.isFixedSize()) {
			createType(BaseNode.BITS, before);
		}

		if (!type.isAnonymous()) {
			builder.add(DwarfAttr.NAME, DwarfForm.STRING, type.name);
		}

		builder.add(DwarfAttr.BYTE_SIZE, DwarfForm.DATA2, buffer -> buffer.putShort(type.size(bytes)));
		SegmentedBuffer inner = builder.done();

		int offset = 0;

		for (StructNode.Entry entry : type.fields) {

			final int current = offset;

			// reference types we already pre-cached before
			DataWriter typeBuffer = types.get(entry.type);

			if (typeBuffer == null) {
				throw new RuntimeException("Undefined type in tree refed by name '" + entry.name + "' (" + entry.type + "), is the type model not a tree?");
			}

			if (entry.isBitField()) {

				create(DwarfTag.MEMBER, dies)
						.add(DwarfAttr.NAME, DwarfForm.STRING, entry.name)
						.add(DwarfAttr.DATA_BIT_OFFSET, DwarfForm.DATA2, buffer -> buffer.putShort(current))
						.add(DwarfAttr.BIT_SIZE, DwarfForm.DATA2, buffer -> buffer.putShort(entry.bits))
						.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> typeBuffer.from(info)))
						.done();

				offset += entry.bits;
				continue;
			}

			create(DwarfTag.MEMBER, dies)
					.add(DwarfAttr.NAME, DwarfForm.STRING, entry.name)
					.add(DwarfAttr.DATA_MEMBER_LOCATION, DwarfForm.DATA2, buffer -> buffer.putShort(current / 8))
					.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> typeBuffer.from(info)))
					.done();

			// keep the offset in bits
			offset += entry.type.size(bytes) * 8;
		}

		if (type.isFixedSize()) {

			final int remaining = type.getFixedSize() * 8 - offset;

			// make sure our bitfield isn't too small
			if (remaining > 0) {

				// reference types we already pre-cached before
				DataWriter field = types.get(BaseNode.BITS);

				final int current = offset;

				create(DwarfTag.MEMBER, dies)
						.add(DwarfAttr.NAME, DwarfForm.STRING, "padding")
						.add(DwarfAttr.DATA_BIT_OFFSET, DwarfForm.DATA2, buffer -> buffer.putShort(current))
						.add(DwarfAttr.BIT_SIZE, DwarfForm.DATA2, buffer -> buffer.putShort(remaining))
						.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> field.from(info)))
						.done();
			}

		}

		dies.putByte(0);
		return inner;
	}

	private DataWriter fromTypedefNode(TypedefNode type, SegmentedBuffer dies) {
		SegmentedBuffer before = dies.putSegment();

		final Builder builder = beginType(type, DwarfTag.TYPEDEF, dies);
		final DataWriter underlying = createType(type.underlying, before);

		builder.add(DwarfAttr.NAME, DwarfForm.STRING, type.name);
		builder.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> underlying.from(info)));

		return builder.done();
	}

	private DataWriter fromPointerNode(PointerNode type, SegmentedBuffer dies) {
		SegmentedBuffer before = dies.putSegment();

		final Builder builder = beginType(type, DwarfTag.POINTER_TYPE, dies);
		final DataWriter underlying = createType(type.reference, before);

		builder.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> underlying.from(info)));

		return builder.done();
	}

	private DataWriter fromIntegerEnumNode(IntegerEnumNode type, SegmentedBuffer dies) {
		DataWriter underlying = createType(type.underlying, dies);

		// integer enums are based on BaseNodes, so it's fine if we first resolve before creating the node
		SegmentedBuffer inner = beginType(type, DwarfTag.ENUMERATION_TYPE, dies).withChildren()
				.add(DwarfAttr.NAME, DwarfForm.STRING, type.name)
				.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> underlying.from(info)))
				.done();

		for (IntegerEnumNode.Enumerator entry : type.enumerators) {

			create(DwarfTag.ENUMERATOR, dies)
					.add(DwarfAttr.NAME, DwarfForm.STRING, entry.name)
					.add(DwarfAttr.CONST_VALUE, DwarfForm.DATA8, buffer -> buffer.putLong(entry.value))
					.done();

		}

		dies.putByte(0);
		return inner;
	}

	private DataWriter fromFunctionNode(FunctionNode type, SegmentedBuffer dies) {
		SegmentedBuffer before = dies.putSegment();
		Builder builder = beginType(type, DwarfTag.SUBPROGRAM, dies).withChildren();

		DataWriter returnType =  createType(type.result, before);

		for (FunctionNode.Variable entry : type.variables) {
			createType(entry.type, before);
		}

		builder.add(DwarfAttr.NAME, DwarfForm.STRING, type.name);
		builder.add(DwarfAttr.LOW_PC, DwarfForm.DATA8, buffer -> buffer.putLong(type.low));
		builder.add(DwarfAttr.HIGH_PC, DwarfForm.DATA8, buffer -> buffer.putLong(type.high));
		builder.add(DwarfAttr.FRAME_BASE, DwarfForm.EXPRLOC, DwarfExpression.from(expr -> expr.putByte(DwarfOp.CALL_FRAME_CFA)));

		if (returnType != null) {
			builder.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> returnType.from(info)));
		}

		SegmentedBuffer inner = builder.done();

		for (FunctionNode.Variable entry : type.getStoredVariables()) {

			final DataWriter parameterBuffer = createType(entry.type, dies);
			final int tag = entry.parameter ? DwarfTag.FORMAL_PARAMETER : DwarfTag.VARIABLE;
			final Storage storage = entry.storage;

			Builder paramBuilder = create(tag, dies)
					.add(DwarfAttr.NAME, DwarfForm.STRING, entry.name)
					.add(DwarfAttr.TYPE, DwarfForm.REF4, buffer -> buffer.putInt(() -> parameterBuffer.from(info)));

			try {
				if (storage.hasLocation()) {
					if (storage instanceof DynamicStorage where) {

						LocationList list = createLocationLists().addLocationSet();

						for (DynamicStorage.Range range : where.ranges) {
							list.addBounded(range.start, range.end, range.storage.asExpression(getAddressWidth()));
						}

						paramBuilder.add(DwarfAttr.LOCATION, DwarfForm.SEC_OFFSET, buffer -> buffer.putInt(list.offset));
					} else {
						paramBuilder.add(DwarfAttr.LOCATION, DwarfForm.EXPRLOC, DwarfExpression.from(storage.asExpression(getAddressWidth())));
					}
				}

				// rethrow with more useful details
			} catch (Exception e) {
				paramBuilder.done();
				throw new RuntimeException("Error creating local '" + entry.name + "' for function: " + type.name, e);
			}

			if (storage instanceof ConstStorage where) {
				paramBuilder.add(DwarfAttr.CONST_VALUE, DwarfForm.DATA8, buffer -> buffer.putLong(where.value));
			}

			paramBuilder.done();
		}

		createSymbol(type.name, type.low, type.size(getAddressWidth()), ElfSymbolFlag.GLOBAL | ElfSymbolFlag.OBJECT, bss);

		dies.putByte(0);
		return inner;
	}

	public int getAddressWidth() {
		return bytes;
	}

	private void assertNoHolders() {
		if (!holders.isEmpty()) {
			final String issues = holders.stream()
					.mapToInt(builder -> builder.tag).distinct()
					.mapToObj(tag -> Reflect.constValueName(DwarfTag.class, tag))
					.collect(Collectors.joining(", "));

			throw new RuntimeException("Some intrusive holders were not yet done building, did you forget to call Builder#done()? In reference to DWARF tags: " + issues);
		}
	}

	@Override
	public void close() {
		assertNoHolders();
		super.close();
	}
}
