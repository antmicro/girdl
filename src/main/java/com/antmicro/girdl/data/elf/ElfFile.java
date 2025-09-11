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

import com.antmicro.girdl.data.bin.ContentPolicy;
import com.antmicro.girdl.data.bin.SegmentedBuffer;
import com.antmicro.girdl.data.bin.SegmentedFile;
import com.antmicro.girdl.data.elf.enums.ElfClass;
import com.antmicro.girdl.data.elf.enums.ElfData;
import com.antmicro.girdl.data.elf.enums.ElfSectionFlag;
import com.antmicro.girdl.data.elf.enums.ElfSectionType;
import com.antmicro.girdl.data.elf.enums.ElfType;

import java.io.File;
import java.nio.ByteOrder;

public class ElfFile implements AutoCloseable {

	public static final int ELF_VERSION = 1;
	public static final int UNDEF_SECTION = 0;
	public static final String SECTION_STRINGS = ".shstrtab";

	private final SegmentedFile file;

	private final SegmentedBuffer shdrs; // section header container block
	private final SegmentedBuffer sdats; // section data container block
	private SegmentedBuffer shstrtab;

	private final SegmentedBuffer symbols;
	private final SegmentedBuffer strings;

	public ElfFile(File file, /* ElfMachine */ int machine) {
		this.file = new SegmentedFile(file, ByteOrder.LITTLE_ENDIAN);

		SegmentedBuffer root = this.file.getRootBuffer();
		SegmentedBuffer header = root.putSegment().setName("ELF Header");

		shdrs = root.putSegment().setName("headers").setPolicy(ContentPolicy.SEGMENTS);
		sdats = root.putSegment().setName("buffers").setPolicy(ContentPolicy.SEGMENTS);

		createSection("", ElfSectionType.NULL, ElfSectionFlag.NONE, 0, 0, null); // special empty section
		createSection(SECTION_STRINGS, ElfSectionType.STRTAB, ElfSectionFlag.NONE, 0, 0, null); // section string table

		strings = createSection(".strtab", ElfSectionType.STRTAB, ElfSectionFlag.NONE, 0, 0, null);
		symbols = createSection(".symtab", ElfSectionType.SYMTAB, ElfSectionFlag.NONE, 8, 0x18, strings);

		strings.putByte(0);

		// ELF identification, 16 bytes
		SegmentedBuffer magic = header.putSegment().setName("ELF Identification");
		magic.putBytes(0x7f, 'E', 'L', 'F');
		magic.putByte(ElfClass.BIT_64);
		magic.putByte(ElfData.LSB_2);
		magic.putByte(ELF_VERSION);
		magic.fillUpToWith(16, 0);

		// ELF header
		header.putShort(ElfType.REL);
		header.putShort(machine);
		header.putInt(ELF_VERSION);
		header.putLong(0); // entry point
		header.putLong(0); // program header offset
		header.putLong(shdrs::offset); // section header offset

		header.putInt(0); // flags
		header.putShort(header::size); // header size
		header.putShort(0); // program header size
		header.putShort(0); // program header number
		header.putShort(() -> shdrs.children().getFirst().size()); // section header size
		header.putShort(() -> shdrs.children().size()); // section header number
		header.putShort(() -> sdats.indexOf(shstrtab)); // string section index

		header.putShort(0); // section header size
		header.putShort(0); // section header number
		header.putShort(0); // string section index
	}

	@Override
	public void close() {
		file.close();
	}

	/**
	 * Create a simple symbol, the ElfSymbolFlag.LOCAL flag is no supported,
	 * the symbol will refer to the given section (must be a member of sdata!).
	 *
	 * @param name Name of the symbol to create
	 * @param address Offset from section address
	 * @param size Number of bytes in the symbol, or zero if not known
	 * @param flag One of the ElfSymbolFlags, except LOCAL
	 */
	public void createSymbol(String name, long address, int size, /* ElfSymbolFlag */ int flag, SegmentedBuffer section) {
		int offset = strings.size();
		strings.putString(name);

		// symbol definition
		symbols.putInt(offset);
		symbols.putByte(flag); // info
		symbols.putByte(0); // other
		symbols.putShort(sdats.indexOf(section)); // section
		symbols.putLong(address);
		symbols.putLong(size);
	}

	/**
	 * Create a section of the given name, two default section (empty and section strings section) are created
	 * in the constructor.
	 *
	 * @param name Name of the section to create, should start with '.'
	 * @param type One of ElfSectionType values
	 * @param align Required section alignment
	 * @param element Element size, by default use 0
	 * @param linked The buffer "linked" to this section using sh_link, can be null
	 */
	public SegmentedBuffer createSection(String name, /* ElfSectionType */ int type, /* ElfSectionFlag */ int flags, int align, int element, SegmentedBuffer linked) {
		SegmentedBuffer header = shdrs.putSegment().setName(name).setPolicy(ContentPolicy.DATA);
		SegmentedBuffer content = sdats.putSegment().setName(name).setAlignment(align);

		boolean empty = (type == ElfSectionType.NULL);

		if (name.equals(SECTION_STRINGS)) {
			// string tables must start with \0
			content.putByte(0);
			shstrtab = content;
		}

		header.putInt(shstrtab == null ? 0 : shstrtab.size()); // name offset
		header.putInt(type); // section type
		header.putLong(flags); // flags
		header.putLong(0); // address

		if (!empty) {
			header.putLong(content::offset);
			header.putLong(content::size);
		} else {
			header.putSpace(16, 0);
		}

		header.putInt(linked == null ? UNDEF_SECTION : sdats.indexOf(linked)); // link
		header.putInt(UNDEF_SECTION); // info
		header.putLong(align); // addralign
		header.putLong(element); // entry size

		if (!name.isEmpty()) {
			shstrtab.putString(name);
		}

		return content;
	}

}
