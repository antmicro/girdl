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
package com.antmicro.girdl.export;

import com.antmicro.girdl.data.elf.Storage;
import com.antmicro.girdl.data.elf.storage.DynamicStorage;
import com.antmicro.girdl.data.elf.storage.StaticStorage;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class PcodeUtils {

	public static final Range INVARIANT = new Range(0);

	public static class Range {

		private final long writeCount;
		private final long firstWrite;
		private final long lastWrite;

		public Range(long address) {
			this.firstWrite = address;
			this.lastWrite = address;
			this.writeCount = 1;
		}

		private Range(long first, long last, long count) {
			this.firstWrite = first;
			this.lastWrite = last;
			this.writeCount = count;
		}

		public Range includeWrite(long address) {
			return new Range(Math.min(firstWrite, address), Math.max(lastWrite, address), writeCount + 1);
		}

		/**
		 * Does this range represent a constant variable,
		 * that is, it is only written to once.
		 */
		boolean isConst() {
			return writeCount <= 1;
		}

		/**
		 * Remap the given storage so that it better describes,
		 * the symbol's lifetime.
		 */
		Storage wrap(HighSymbol symbol, StaticStorage storage, long functionStartAddress, long functionEndAddress, long offset) {

			long firstByte = functionStartAddress + offset;
			long lastByte = functionEndAddress + offset;

			// This can occur (normally) only for const function parameters
			if (writeCount > 0) {
				lastByte = lastWrite + offset;
			}

			// Technically == should be fine here (we are checking if the write did not occur at the first instruction
			// of a function, and if so expanding the end by one byte, as empty/negative ranges are not allowed in DWARF)
			if (lastByte <= firstByte) {
				lastByte = firstByte + 1;
			}

			// parameters that are not written to according to ghidra can be made invariant by holding the initial 'entry' value
			if (isConst() && symbol.isParameter()) {
				return Storage.ofRanges(DynamicStorage.newRange(firstByte, lastByte, storage));
			}

			// make locals only visible after their value is written for the first time
			if ((writeCount > 0) && !symbol.isParameter()) {
				return Storage.ofRanges(DynamicStorage.newRange(firstWrite + offset + 1, functionEndAddress + offset, storage));
			}

			return storage;

		}

	}

	public static class RangeMap {

		private final Map<Address, Range> ranges = new HashMap<>();

		/**
		 * Get the range for specific varnode address,
		 * or (if unavailable) an empty optional.
		 */
		public Optional<Range> getRangeFor(Address address) {
			return Optional.ofNullable(ranges.get(address));
		}

	}

	/**
	 * Create a map that identifies the program address where the first/last write operation
	 * occurs to the given Address (register, stack, memory, ...).
	 */
	public static RangeMap toVarnodeRangeMap(Iterator<PcodeOpAST> ops) {
		RangeMap map = new RangeMap();

		ops.forEachRemaining(ast -> {

			if (ast.isAssignment()) {
				Varnode node = ast.getOutput();
				long address = ast.getSeqnum().getTarget().getOffset();

				map.ranges.compute(node.getAddress(), (key, prev) -> prev == null ? new Range(address) : prev.includeWrite(address));
			}
		});

		return map;
	}

	/**
	 * Convert varnode to a more readable form when possible,
	 * otherwise just convert it directly to string as-is.
	 */
	private static String varnodeToString(Varnode varnode) {
		if (varnode == null) {
			return null;
		}

		Address address = varnode.getAddress();

		if (varnode.isConstant()) {
			return Long.toString(address.getOffset());
		}

		if (varnode.isAddress()) {
			return "[0x" + Long.toHexString(address.getOffset()) + "]";
		}

		if (varnode.isRegister()) {
			return "r" + address.getOffset();
		}

		if (varnode.isUnique()) {
			return "u" + address.getOffset();
		}

		return address.toString();
	}

	/**
	 * Helper function to print the PCode of a given decompiled function
	 * to the standard output.
	 */
	public static void dump(HighFunction function) {
		System.out.println("\nprocedure " + function.getFunction().getName());

		Set<Long> labels = new HashSet<>();

		function.getPcodeOps().forEachRemaining(ast -> {
			int opcode = ast.getOpcode();

			if (opcode == PcodeOp.CBRANCH) {
				labels.add(ast.getInputs()[0].getOffset());
			}
		});

		function.getPcodeOps().forEachRemaining(ast -> {
			int opcode = ast.getOpcode();
			String name = PcodeOp.getMnemonic(opcode);

			final List<String> args = new ArrayList<>();
			String output = varnodeToString(ast.getOutput());

			if (output != null) {
				args.add(output);
			}

			long address = ast.getParent().getStart().getOffset();

			if (labels.contains(address)) {
				labels.remove(address);
				System.out.println("\n\tl_" + Long.toHexString(address));
			}

			Arrays.stream(ast.getInputs()).map(PcodeUtils::varnodeToString).forEach(args::add);
			System.out.println("\t" + String.format("%08x: ", address) + name + " " + String.join(", ", args));
		});
	}

}
