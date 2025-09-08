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
package com.antmicro.girdl.data.svd;

import java.util.Optional;

public class SvdField {

	public String name;
	public Optional<String> description;

	public Optional<String> bitOffset;
	public Optional<String> bitWidth;
	public Optional<String> lsb;
	public Optional<String> msb;
	public Optional<String> bitRange;

	public Range getBitRange() {
		if (bitOffset.isPresent() && bitWidth.isPresent()) {
			return Range.ofOffsetWidth(Integer.decode(bitOffset.get()), Integer.decode(bitWidth.get()));
		}

		if (lsb.isPresent() && msb.isPresent()) {
			return Range.ofFirstLast(Integer.decode(lsb.get()), Integer.decode(msb.get()));
		}

		if (bitRange.isPresent()) {
			return Range.ofPattern(bitRange.get());
		}

		throw new RuntimeException("No size specified for field '" + name + "'!");
	}

	public static class Range {

		public final long start;
		public final long size ;

		private Range(long start, long size) {
			this.start = start;
			this.size = size;
		}

		private static Range ofOffsetWidth(long offset, long width) {
			return new Range(offset, width);
		}

		private static Range ofFirstLast(long lsb, long msb) {
			long min = Math.min(lsb, msb);
			long max = Math.max(lsb, msb);

			return ofOffsetWidth(min, max - min + 1);
		}

		/// String in the format "[<msb>:<lsb>]".
		private static Range ofPattern(String pattern) {
			String[] parts = pattern.split(":");

			if (parts.length != 2) {
				throw new RuntimeException("Expected two pattern parts!");
			}

			if (!parts[0].startsWith("[")) {
				throw new RuntimeException("Pattern should be enclosed in square brackets!");
			}

			if (!parts[1].endsWith("]")) {
				throw new RuntimeException("Pattern should be enclosed in square brackets!");
			}

			long msb = Long.decode(parts[0].substring(1));
			long lsb = Long.decode(parts[1].substring(0, parts[1].length() - 1));

			return ofFirstLast(lsb, msb);
		}

	}

}
