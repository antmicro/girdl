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
package com.antmicro.girdl.data.elf.storage;

import com.antmicro.girdl.data.elf.Storage;

import java.util.Collections;
import java.util.List;

/**
 * Represents elements whose storage may change during execution,
 * it defines a set of program counter ranges each specifying a static storage for that range.
 */
public class DynamicStorage extends Storage {

	public final List<Range> ranges;

	public DynamicStorage(List<Range> ranges) {
		this.ranges = Collections.unmodifiableList(ranges);
	}

	public static class Range {

		public final long start;
		public final long end;
		public final StaticStorage storage;

		private Range(long start, long end, StaticStorage storage) {
			this.start = start;
			this.end = end;
			this.storage = storage;
		}

	}

	public static Range newRange(long start, long end, StaticStorage storage) {
		if (start > end) {
			throw new RuntimeException("Invalid range, the range ends (" + Long.toHexString(end) + ") before it starts (" + Long.toHexString(start) + ")!");
		}

		return new Range(start, end, storage);
	}

	@Override
	public boolean isKnown() {
		return !ranges.isEmpty();
	}

	@Override
	public boolean hasLocation() {
		return isKnown();
	}

}
