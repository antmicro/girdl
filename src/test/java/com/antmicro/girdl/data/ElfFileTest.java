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
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.test.Util;
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

		String all = Util.getCommandOutput("readelf",  "-aw", temp.getAbsolutePath());
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String header = Util.getCommandOutput("readelf", "-h", temp.getAbsolutePath());
		Assertions.assertTrue(header.contains("REL (Relocatable file)"));
		Assertions.assertTrue(header.contains("Advanced Micro Devices X86-64"));
		Assertions.assertTrue(header.contains("2's complement, little endian"));

		// check that there is no executable code in the generated file
		String segments = Util.getCommandOutput("readelf", "-l", temp.getAbsolutePath());
		Assertions.assertTrue(segments.contains("There are no program headers in this file."));

		String sections = Util.getCommandOutput("readelf", "-S", temp.getAbsolutePath());
		Assertions.assertTrue(sections.contains(".shstrtab         STRTAB"));
		Assertions.assertTrue(sections.contains(".strtab           STRTAB"));
		Assertions.assertTrue(sections.contains(".symtab           SYMTAB"));
		Assertions.assertTrue(sections.contains(".bss              NOBITS"));
		Assertions.assertFalse(sections.contains(".text")); // and no executable code to link with

		String symbols = Util.getCommandOutput("readelf", "-s", temp.getAbsolutePath());
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

		Assertions.assertEquals(16, outer.size());

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.X86_64, 64)) {
			dwarf.createVariable(outer, "name", 0x1234567890L);
		}

		String all = Util.getCommandOutput("readelf",  "-aw", temp.getAbsolutePath());
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String sections = Util.getCommandOutput("readelf", "-S", temp.getAbsolutePath());
		Assertions.assertTrue(sections.contains(".bss              NOBITS"));
		Assertions.assertTrue(sections.contains(".debug_info       PROGBITS"));
		Assertions.assertTrue(sections.contains(".debug_abbrev     PROGBITS"));
		Assertions.assertFalse(sections.contains(".text"));

		String segments = Util.getCommandOutput("readelf", "-l", temp.getAbsolutePath());
		Assertions.assertTrue(segments.contains("There are no program headers in this file."));

		String symbols = Util.getCommandOutput("readelf", "-s", temp.getAbsolutePath());
		Assertions.assertTrue(symbols.contains("0: 0000001234567890    16 OBJECT  GLOBAL DEFAULT    4 name"));

		String debug = Util.getCommandOutput("readelf", "-w", temp.getAbsolutePath());
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

		Assertions.assertEquals(16, outer.size());

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.X86_64, 64)) {
			dwarf.createVariable(outer, "name", 0x1234567890L);
		}

		String all = Util.getCommandOutput("readelf",  "-aw", temp.getAbsolutePath());
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String symbols = Util.getCommandOutput("readelf", "-s", temp.getAbsolutePath());
		Assertions.assertTrue(symbols.contains("0: 0000001234567890    16 OBJECT  GLOBAL DEFAULT    4 name"));

		String debug = Util.getCommandOutput("readelf", "-w", temp.getAbsolutePath());
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

		Assertions.assertEquals(4, outer.size());

		try (DwarfFile dwarf = new DwarfFile(temp, ElfMachine.I386, 32)) {
			dwarf.createVariable(outer, "name", 0x1234567890L);
		}

		String all = Util.getCommandOutput("readelf",  "-aw", temp.getAbsolutePath());
		Assertions.assertFalse(all.contains("Error"));
		Assertions.assertFalse(all.contains("Warning"));

		String symbols = Util.getCommandOutput("readelf", "-s", temp.getAbsolutePath());
		Assertions.assertTrue(symbols.contains("0: 0000001234567890     4 OBJECT  GLOBAL DEFAULT    4 name"));

		String debug = Util.getCommandOutput("readelf", "-w", temp.getAbsolutePath());
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

}
