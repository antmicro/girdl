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
package com.antmicro.girdl;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class PcodeUtils {

	/**
	 * Create a map that identifies the program address where the first write operation
	 * occurs to the given Address (register, stack, memory, ...)
	 */
	public static Map<Address, Long> toVarnodeWriteMap(Iterator<PcodeOpAST> ops) {
		Map<Address, Long> initial = new HashMap<>();

		ops.forEachRemaining(ast -> {

			if (ast.isAssignment()) {
				Varnode node = ast.getOutput();
				long address = ast.getSeqnum().getTarget().getOffset();

				initial.compute(node.getAddress(), (key, prev) -> prev == null ? address : Math.min(prev, address));
			}
		});

		return initial;
	}

}
