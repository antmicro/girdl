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

import com.antmicro.girdl.data.bin.SegmentedBuffer;
import com.antmicro.girdl.data.elf.enums.DwarfContent;
import com.antmicro.girdl.data.elf.enums.DwarfForm;
import com.antmicro.girdl.data.elf.enums.DwarfLine;
import com.antmicro.girdl.data.elf.source.SourceFactory;

import java.util.HashMap;

public class LineProgrammer {

	public static final int DWARF_VERSION = 5;

	public static final int BYTES_PER_INSTRUCTION = 1;
	public static final int MAX_VLIW_OPERATIONS_PER_INSTRUCTION = 1;
	public static final int DWARF5_OPCODE_COUNT = 13;

	private long address = 0;
	private long line = 1;

	private final SegmentedBuffer head;
	private final SegmentedBuffer body;

	private final SegmentedBuffer directoryCount;
	private final SegmentedBuffer directoryList;
	private final SegmentedBuffer fileCount;
	private final SegmentedBuffer fileList;

	private HashMap<String, Integer> files = new HashMap<>();

	public LineProgrammer(SegmentedBuffer writer, int addressWidth) {
		SegmentedBuffer section = writer.putSegment();
		this.head = section.putSegment().setName("header");
		this.body = section.putSegment().setName("data");

		// see specification 6.2.4
		head.putInt(() -> section.size() - 4); // length (excluding the length field itself)
		head.putShort(DWARF_VERSION); // section version
		head.putByte(addressWidth); // address (pointer) width
		head.putByte(0); // segment selector size (if present)

		SegmentedBuffer length = head.putSegment();
		SegmentedBuffer cont = head.putSegment();

		cont.putByte(BYTES_PER_INSTRUCTION);
		cont.putByte(MAX_VLIW_OPERATIONS_PER_INSTRUCTION);
		cont.putBool(true); // is_statement default value

		// special opcode configuration, as we don't use those we can use minimal allowed values here
		cont.putByte(0); // line_base
		cont.putByte(1); // line_range
		cont.putByte(DWARF5_OPCODE_COUNT);

		// encode the standard opcode argument counts
		for (int i = 1; i < 13; i ++) {
			byte args = 0;

			if (i >= 2 && i <= 5) args = 1;
			if (i == 9 || i == 12) args = 1;

			cont.putByte(args);
		}

		cont.putByte(1); // number of key-value pairs
		cont.putUnsignedLeb128(DwarfContent.PATH).putUnsignedLeb128(DwarfForm.STRING);

		directoryCount = cont.putSegment().setName("directory count");
		directoryList = cont.putSegment().setName("directory list");
		directoryCount.putUnsignedLeb128(0);

		cont.putByte(2); // number of key-value pairs
		cont.putUnsignedLeb128(DwarfContent.PATH).putUnsignedLeb128(DwarfForm.STRING);
		cont.putUnsignedLeb128(DwarfContent.DIRECTORY_INDEX).putUnsignedLeb128(DwarfForm.UDATA);

		fileCount = cont.putSegment().setName("directory count");
		fileList = cont.putSegment().setName("directory list");
		fileCount.putUnsignedLeb128(0);

		length.putInt(cont::size);
	}

	/**
	 * Define include directory.
	 */
	public int addDirectory(String path) {
		int inserted = fileList.children().size();

		directoryList.putSegment().setName("entry").putString(path);
		directoryCount.erase().putUnsignedLeb128(directoryList.children().size());

		return inserted;
	}

	/**
	 * Set the current column in source file.
	 */
	public void setColumn(int column) {
		body.putByte(DwarfLine.SET_COLUMN).putUnsignedLeb128(column);
	}

	/**
	 * Set the current file path.
	 */
	public void setFile(int directory, String path) {
		Integer index = files.get(path);

		if (index != null) {
			body.putByte(DwarfLine.SET_FILE).putUnsignedLeb128(index);
			return;
		}

		int inserted = fileList.children().size();

		fileList.putSegment().setName("entry").putString(path).putUnsignedLeb128(directory);
		fileCount.erase().putUnsignedLeb128(fileList.children().size());
		files.put(path, inserted);

		setFile(directory, path);
	}

	/**
	 * Add the given signed offset to the line register.
	 */
	public void advanceLine(long advance) {
		if (advance == 0) {
			return;
		}

		line += advance;
		body.putByte(DwarfLine.ADVANCE_LINE).putSignedLeb128(advance);
	}

	/**
	 * Add the given unsigned offset to the address register.
	 */
	public void advanceAddress(long advance) {
		if (advance == 0) {
			return;
		}

		if (advance < 0) {
			throw new RuntimeException("Address can only be advanced forward!");
		}

		address += advance;
		body.putByte(DwarfLine.ADVANCE_PC).putUnsignedLeb128(advance);
	}

	/**
	 * Append a new row to the line mapping matrix using current state.
	 */
	public void next() {
		body.putByte(DwarfLine.COPY);
	}

	/**
	 * Mark the one-past-last address, marking the end of valid program addresses.
	 */
	public void endSequence() {
		body.putByte(DwarfLine.EXT_BEGIN);
		body.putUnsignedLeb128(1);
		body.putByte(DwarfLine.EXT_END_SEQUENCE);
	}

	/**
	 * Set the address register to a specific value.
	 */
	public void setAddress(long target) {
		advanceAddress(target - address);
	}

	/**
	 * Set the line register to a specific value.
	 */
	public void setLine(long target) {
		advanceLine(target - line);
	}

	/**
	 * Flush the whole source document into the programmer.
	 */
	public void encodeSource(SourceFactory source, long addend) {

		source.forEachMapped(line -> {
			long offset = line.address + addend;

			setLine(line.line);
			setAddress(offset);
			next();
		});

	}

}
