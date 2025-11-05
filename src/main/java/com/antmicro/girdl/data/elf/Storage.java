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
import com.antmicro.girdl.data.elf.storage.AddressStorage;
import com.antmicro.girdl.data.elf.storage.ConstStorage;
import com.antmicro.girdl.data.elf.storage.DynamicStorage;
import com.antmicro.girdl.data.elf.storage.RegisterStorage;
import com.antmicro.girdl.data.elf.storage.StackStorage;
import com.antmicro.girdl.data.elf.storage.StaticStorage;
import com.antmicro.girdl.data.elf.storage.UnknownStorage;

import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

public abstract class Storage {

	/**
	 * Convert to a raw (no header) DWARF expression.
	 */
	public Consumer<SegmentedBuffer> asExpression(int width) {
		throw new RuntimeException("Can't convert to expression!");
	}

	/**
	 * Check if this is not an undefined storage.
	 */
	public boolean isKnown() {
		return true;
	}

	public boolean hasLocation() {
		return false;
	}

	public static StaticStorage ofAddress(long address) {
		return new AddressStorage(address);
	}

	public static StaticStorage ofStack(long offset) {
		return new StackStorage(offset);
	}

	public static StaticStorage ofDwarfRegister(long register) {
		return new RegisterStorage(register);
	}

	public static StaticStorage ofConst(long value) {
		return new ConstStorage(value);
	}

	public static StaticStorage ofUnknown() {
		return UnknownStorage.INSTANCE;
	}

	public static Storage ofRanges(DynamicStorage.Range... ranges) {
		return new DynamicStorage(Arrays.stream(ranges).toList());
	}

	public static Storage ofRanges(List<DynamicStorage.Range> ranges) {
		return new DynamicStorage(ranges);
	}

}
