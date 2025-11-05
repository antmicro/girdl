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
 * Represents elements stored in processor registers,
 * the exact register is expressed by their DWARF IDs.
 */
public class RegisterStorage extends StaticStorage {

	public final long register;

	public RegisterStorage(long register) {
		this.register = register;
	}

	@Override
	public Consumer<SegmentedBuffer> asExpression(int width) {
		return expr -> expr.putByte(DwarfOp.REGX).putUnsignedLeb128(register);
	}

}
