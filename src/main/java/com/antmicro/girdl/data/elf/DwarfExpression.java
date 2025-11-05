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

import java.util.function.Consumer;

public class DwarfExpression {

	/**
	 * Helper for creating DWARF expressions that wraps them in a lambda
	 * that takes care of creating the expression header that describes the expression size.
	 *
	 * @param writer Raw DWARF expression without headers
	 */
	public static Consumer<SegmentedBuffer> from(Consumer<SegmentedBuffer> writer) {
		return expr -> {
			final SegmentedBuffer head = expr.putSegment();
			final SegmentedBuffer body = expr.putSegment();

			writer.accept(body);

			// not linked, the size can't change past this point!
			head.putUnsignedLeb128(body.size());
		};
	}

}
