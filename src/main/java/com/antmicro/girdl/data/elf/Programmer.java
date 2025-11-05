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

public class Programmer {

	public static final int DWARF_VERSION = 5;

	protected final int addressWidth;
	protected final SegmentedBuffer head;
	protected final SegmentedBuffer body;

	Programmer(SegmentedBuffer writer, int addressWidth) {
		SegmentedBuffer section = writer.putSegment();
		this.head = section.putSegment().setName("header");
		this.body = section.putSegment().setName("data");
		this.addressWidth = addressWidth;

		// see specification 6.2.4
		head.putInt(() -> section.size() - 4); // length (excluding the length field itself)
		head.putShort(DWARF_VERSION); // section version
		head.putByte(addressWidth); // address (pointer) width
		head.putByte(0); // segment selector size (if present)
	}

}
