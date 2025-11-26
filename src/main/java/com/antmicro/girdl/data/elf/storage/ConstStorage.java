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

import com.antmicro.girdl.data.bin.SegmentedBuffer;
import com.antmicro.girdl.data.elf.enums.DwarfOp;

import java.util.function.Consumer;

/**
 * Represents elements that aren't stored in any memory,
 * and instead should be treated as named constants.
 */
public class ConstStorage extends StaticStorage {

	public final long value;

	public ConstStorage(long offset) {
		this.value = offset;
	}

	public boolean hasLocation() {
		return false;
	}

	@Override
	public Consumer<SegmentedBuffer> asExpression(int width) {
		return (DwarfOp.literal(value)
				.<Consumer<SegmentedBuffer>>map(aLong -> expr -> expr.putByte(aLong))
				.orElseGet(() -> expr -> expr.putByte(DwarfOp.CONSTU).putUnsignedLeb128(value)))
				.andThen(expr -> expr.putByte(DwarfOp.STACK_VALUE));
	}

	@Override
	public boolean isUseSiteInvariant() {
		return true;
	}

}
