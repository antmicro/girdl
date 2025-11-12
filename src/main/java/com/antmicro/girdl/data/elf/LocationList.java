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
import com.antmicro.girdl.data.elf.enums.DwarfLoc;

import java.util.function.Consumer;

public class LocationList {

	private final int bits;
	private final SegmentedBuffer buffer;
	public final int offset;

	/// DWARF Specification 2.6.2
	public LocationList(SegmentedBuffer buffer, int offset, int addressWidth) {
		this.buffer = buffer.putSegment();
		this.offset = offset;
		this.bits = addressWidth * 8;

		// the location list must be terminated with an end-of-list marker
		buffer.putByte(DwarfLoc.END_OF_LIST);
	}

	/**
	 * Expression that shall be applied over a range of program
	 * addresses, when no bound expression applies the default will be used, if provided.
	 *
	 * @param start  start address of the bounds of the expression (inclusive)
	 * @param end    end address of the bounds of the expression (exclusive)
	 * @param writer the expression writer
	 */
	public void addBounded(long start, long end, Consumer<SegmentedBuffer> writer) {

		if (start > end) {
			throw new RuntimeException("Invalid bound address descriptor, the range ends (" + Long.toHexString(end) + ") before it starts (" + Long.toHexString(start) + ")!");
		}

		final long length = end - start;

		buffer.putByte(DwarfLoc.START_LENGTH);
		buffer.putDynamic(bits, start);
		buffer.putUnsignedLeb128(length);
		DwarfExpression.from(writer).accept(buffer);
	}

	/**
	 * Writer for the DWARF expression to be used,
	 * the default expression is used when no bounded expression applies and is optional.
	 *
	 * @param writer the expression writer
	 */
	public void addDefault(Consumer<SegmentedBuffer> writer) {
		buffer.putByte(DwarfLoc.DEFAULT_LOCATION);
		DwarfExpression.from(writer).accept(buffer);
	}

}
