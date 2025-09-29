package com.antmicro.girdl.data;

import com.antmicro.girdl.data.elf.DwarfFile;
import com.antmicro.girdl.data.elf.ElfFile;
import com.antmicro.girdl.data.elf.enums.ElfMachine;
import com.antmicro.girdl.data.elf.enums.ElfSectionFlag;
import com.antmicro.girdl.data.elf.enums.ElfSectionType;
import com.antmicro.girdl.data.elf.enums.ElfSymbolFlag;
import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.BitsNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.model.type.TypedefNode;
import com.antmicro.girdl.model.type.UnionNode;
import com.antmicro.girdl.test.Util;
import com.antmicro.girdl.util.log.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;

public class ElfFileTest {

	@Test
	void testElfFile() {

		File temp = Util.createTempFile(".elf");

		try (ElfFile elf = new ElfFile(temp, ElfMachine.X86_64)) {
			var bss = elf.createSection(".bss", ElfSectionType.NOBITS, ElfSectionFlag.WRITE | ElfSectionFlag.ALLOC, 32, 0, null);
			elf.createSymbol("SYMBOL_NAME", 0x1122334455667788L, 4, ElfSymbolFlag.GLOBAL | ElfSymbolFlag.OBJECT, bss);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String header = Util.runCommand("readelf", "-h", temp.getAbsolutePath()).output();
		Assertions.assertTrue(header.contains("REL (Relocatable file)"));
		Assertions.assertTrue(header.contains("Advanced Micro Devices X86-64"));
		Assertions.assertTrue(header.contains("2's complement, little endian"));

		// check that there is no executable code in the generated file
		String segments = Util.runCommand("readelf", "-l", temp.getAbsolutePath()).output();
		Assertions.assertTrue(segments.contains("There are no program headers in this file."));

		String sections = Util.runCommand("readelf", "-S", temp.getAbsolutePath()).output();
		Assertions.assertTrue(sections.contains(".shstrtab         STRTAB"));
		Assertions.assertTrue(sections.contains(".strtab           STRTAB"));
		Assertions.assertTrue(sections.contains(".symtab           SYMTAB"));
		Assertions.assertTrue(sections.contains(".bss              NOBITS"));
		Assertions.assertFalse(sections.contains(".text")); // and no executable code to link with

		String symbols = Util.runCommand("readelf", "-s", temp.getAbsolutePath()).output();
		Assertions.assertTrue(symbols.contains("0: 1122334455667788     4 OBJECT  GLOBAL DEFAULT    4 SYMBOL_NAME"));

	}

	@Test
	void testInvalidDwarfBits() {

		File temp = Util.createTempFile(".dwarf");

		Assertions.assertThrows(RuntimeException.class, () -> new DwarfFile(temp, ElfMachine.X86_64, 65));
		Assertions.assertThrows(RuntimeException.class, () -> new DwarfFile(temp, ElfMachine.X86_64, 30));
		Assertions.assertThrows(RuntimeException.class, () -> new DwarfFile(temp, ElfMachine.X86_64, 7));
		Assertions.assertThrows(RuntimeException.class, () -> new DwarfFile(temp, ElfMachine.X86_64, 0));

	}

	@Test
	void testDwarfFile() {

		File temp = Util.createTempFile(".dwarf");

		StructNode outer = StructNode.of("PAIR")
				.addField(BaseNode.of(8), "first", "first value")
				.addField(BaseNode.of(8), "second", "first value");

		Assertions.assertEquals(16, outer.size(4));

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.X86_64, 64)) {
			dwarf.createVariable(outer, "name", 0x1234567890L);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String sections = Util.runCommand("readelf", "-S", temp.getAbsolutePath()).output();
		Assertions.assertTrue(sections.contains(".bss              NOBITS"));
		Assertions.assertTrue(sections.contains(".debug_info       PROGBITS"));
		Assertions.assertTrue(sections.contains(".debug_abbrev     PROGBITS"));
		Assertions.assertFalse(sections.contains(".text"));

		String segments = Util.runCommand("readelf", "-l", temp.getAbsolutePath()).output();
		Assertions.assertTrue(segments.contains("There are no program headers in this file."));

		String symbols = Util.runCommand("readelf", "-s", temp.getAbsolutePath()).output();
		Assertions.assertTrue(symbols.contains("0: 0000001234567890    16 OBJECT  GLOBAL DEFAULT    4 name"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_AT_producer    : girdl"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : peripherals"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : uint64_t"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : first"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : second"));
		Assertions.assertTrue(debug.contains("DW_OP_addr: 1234567890"));

	}

	@Test
	void testDwarfFileWithArray() {

		File temp = Util.createTempFile(".dwarf");

		StructNode outer = StructNode.of("PAIR")
				.addField(ArrayNode.of(
						StructNode.of("ELEM")
								.addField(BaseNode.of(1), "a", "")
								.addField(BaseNode.of(1), "b", ""),
						4), "first", "first value")
				.addField(BaseNode.of(8), "last", "first value");

		Assertions.assertEquals(16, outer.size(4));

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.X86_64, 64)) {
			dwarf.createVariable(outer, "name", 0x1234567890L);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String symbols = Util.runCommand("readelf", "-s", temp.getAbsolutePath()).output();
		Assertions.assertTrue(symbols.contains("0: 0000001234567890    16 OBJECT  GLOBAL DEFAULT    4 name"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_TAG_array_type"));
		Assertions.assertTrue(debug.contains("DW_TAG_subrange_type"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : PAIR"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : ELEM"));
		Assertions.assertTrue(debug.contains("DW_AT_upper_bound : 4"));
		Assertions.assertTrue(debug.contains("DW_AT_data_member_location: 0"));

	}

	@Test
	void testDwarfFileWithBitfields() {

		File temp = Util.createTempFile(".dwarf");

		BitsNode outer = BitsNode.of(BaseNode.of(4))
				.addField(4, "bf_1", "")
				.addField(2, "bf_2", "")
				.addField(2, "bf_3", "")
				.addField(24, "bf_4", "");

		Assertions.assertEquals(4, outer.size(4));

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createVariable(outer, "name", 0x1234567890L);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String symbols = Util.runCommand("readelf", "-s", temp.getAbsolutePath()).output();
		Assertions.assertTrue(symbols.contains("0: 0000001234567890     4 OBJECT  GLOBAL DEFAULT    4 name"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_AT_name        : bf_1"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : bf_2"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : bf_3"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : bf_4"));
		Assertions.assertTrue(debug.contains("DW_AT_bit_size    : 2"));
		Assertions.assertTrue(debug.contains("DW_AT_bit_size    : 4"));
		Assertions.assertTrue(debug.contains("DW_AT_bit_size    : 24"));
		Assertions.assertTrue(debug.contains("DW_AT_data_bit_offset: 0"));
		Assertions.assertTrue(debug.contains("DW_AT_data_bit_offset: 4"));
		Assertions.assertTrue(debug.contains("DW_AT_data_bit_offset: 6"));
		Assertions.assertTrue(debug.contains("DW_AT_data_bit_offset: 8"));

	}

	@Test
	void testDwarfFileWithTypedef() {

		File temp = Util.createTempFile(".dwarf");

		TypedefNode typedef = TypedefNode.of(BaseNode.of(4, "named_4_bytes"), "another");

		Assertions.assertEquals(4, typedef.size(4));

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createType(typedef);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_TAG_base_type"));
		Assertions.assertTrue(debug.contains("DW_TAG_typedef"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : named_4_bytes"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : another"));
		Assertions.assertTrue(debug.contains("DW_AT_type        :"));

		String debugger = Util.runCommand("gdb", temp.getAbsolutePath()).withInput("add-symbol-file " + temp.getAbsolutePath() + "\ninfo types").output();

		Assertions.assertTrue(debugger.contains("""
				(gdb) All defined types:
				
				File peripherals:
					typedef named_4_bytes another;
					named_4_bytes"""));

	}

	@Test
	void testDwarfFileWithPointer() {

		File temp = Util.createTempFile(".dwarf");

		TypeNode type = TypedefNode.of(PointerNode.of(BaseNode.of(4, "named_4_bytes")), "ptr");

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createType(type);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_TAG_base_type"));
		Assertions.assertTrue(debug.contains("DW_TAG_pointer_type"));

		String debugger = Util.runCommand("gdb", temp.getAbsolutePath()).withInput("add-symbol-file " + temp.getAbsolutePath() + "\ninfo types").output();

		Assertions.assertTrue(debugger.contains("""
				(gdb) All defined types:
				
				File peripherals:
					named_4_bytes
					typedef named_4_bytes * ptr;"""));

	}

	@Test
	void testDwarfFileWithEnum() {

		File temp = Util.createTempFile(".dwarf");

		IntegerEnumNode type = IntegerEnumNode.of("my_enum", BaseNode.of(4));
		type.addEnumerator("A", 123);
		type.addEnumerator("B", 0xffff);
		type.addEnumerator("C", 0xCCCCCCCCL);

		Assertions.assertEquals(4, type.size(4));

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createType(type);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_TAG_enumeration_type"));
		Assertions.assertTrue(debug.contains("DW_TAG_enumerator"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : my_enum"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : A"));
		Assertions.assertTrue(debug.contains("DW_AT_const_value : 0x7b"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : B"));
		Assertions.assertTrue(debug.contains("DW_AT_const_value : 0xffff"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : C"));
		Assertions.assertTrue(debug.contains("DW_AT_const_value : 0xcccccccc"));

		String debugger = Util.runCommand("gdb", temp.getAbsolutePath()).withInput("add-symbol-file " + temp.getAbsolutePath() + "\nptype enum my_enum").output();

		Assertions.assertTrue(debugger.contains("(gdb) type = enum my_enum {A = 123, B = 65535, C = 3435973836}"));

	}

	@Test
	void testDwarfFileWithFunction() {

		File temp = Util.createTempFile(".dwarf");

		FunctionNode type = FunctionNode.of(BaseNode.of(3, "int"), "foo");
		type.addParameter("a", BaseNode.of(4, "int"));
		type.addParameter("b", BaseNode.of(8, "long"));
		type.addParameter("c", BaseNode.of(8, "long"));
		type.setCodeSpan(0x0000F032, 0x0000FE00);

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createType(type);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_TAG_base_type"));
		Assertions.assertTrue(debug.contains("DW_TAG_subprogram"));
		Assertions.assertTrue(debug.contains("DW_TAG_formal_parameter"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : a"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : b"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : c"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : long"));

		String functions = Util.runCommand("gdb", temp.getAbsolutePath()).withInput("add-symbol-file " + temp.getAbsolutePath() + "\ninfo functions").output();
		Assertions.assertTrue(functions.contains("""
				(gdb) All defined functions:
				
				File peripherals:
					static int foo(int, long, long);
				"""));

		String symbol = Util.runCommand("gdb", temp.getAbsolutePath()).withInput("add-symbol-file " + temp.getAbsolutePath() + "\ninfo address foo").output();
		Assertions.assertTrue(symbol.contains("(gdb) Symbol \"foo\" is a function at address 0xf032."));

	}

	@Test
	void testDwarfFileWithUnion() {

		File temp = Util.createTempFile(".dwarf");

		UnionNode type = UnionNode.of("my_union");
		type.addField(StructNode.of("Pos")
				.addField(BaseNode.of(4), "x", "")
				.addField(BaseNode.of(4), "y", ""), "a", "");
		type.addField(BaseNode.of(4), "b", "");
		type.addField(BaseNode.of(2), "c", "");

		Assertions.assertEquals(8, type.size(4));

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createType(type);
		}

		String all = Util.runCommand("readelf",  "-aw", temp.getAbsolutePath()).error();
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String debug = Util.runCommand("readelf", "-w", temp.getAbsolutePath()).output();
		Assertions.assertTrue(debug.contains("DW_TAG_union"));
		Assertions.assertTrue(debug.contains("DW_TAG_structure"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : my_union"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : x"));
		Assertions.assertTrue(debug.contains("DW_AT_name        : y"));

		String debugger = Util.runCommand("gdb", temp.getAbsolutePath()).withInput("add-symbol-file " + temp.getAbsolutePath() + "\nptype union my_union").output();
		Assertions.assertTrue(debugger.contains("""
				(gdb) type = union my_union {
				    struct Pos a;
				    uint32_t b;
				    uint16_t c;
				}
				"""));

	}

}
