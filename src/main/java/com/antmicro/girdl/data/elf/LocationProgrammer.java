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

public final class LocationProgrammer extends Programmer {

	/// DWARF Specification 7.29
	LocationProgrammer(SegmentedBuffer writer, int addressWidth) {
		super(writer, addressWidth);

		// omit location offset array
		head.putInt(0);
	}

	/**
	 * Create a new DWARF Location List, the .offset value can be used
	 * to reference it from DWARF expressions.
	 */
	public LocationList addLocationSet() {
		final SegmentedBuffer buffer = body.putSegment();
		return new LocationList(buffer, body.offsetOf(buffer) + head.size(), addressWidth);
	}

}
