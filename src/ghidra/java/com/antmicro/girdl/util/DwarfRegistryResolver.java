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
package com.antmicro.girdl.util;

import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappings;
import ghidra.app.util.bin.format.dwarf.DWARFRegisterMappingsManager;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

import java.util.HashMap;
import java.util.Map;

public class DwarfRegistryResolver {

	private int nextDwarfOffset = 0;

	private final DWARFRegisterMappings registers;
	private final Map<Integer, Integer> mapping = new HashMap<>();

	public DwarfRegistryResolver(Language language) {
		registers = Functional.except(() -> DWARFRegisterMappingsManager.getMappingForLang(language)).orElseThrow();
	}

	public int getDwarfRegister(Register register) {

		int offset = register.getOffset();
		Integer dwarf = mapping.get(offset);

		if (dwarf != null) {
			return dwarf;
		}

		// just an upper limit so that we can't fall into an infinite loop here
		// the number was chosen arbitrary, and needs to be larger or equal to the
		// largest register count of any supported instruction set
		for (int i = 0; i < 1000; i ++) {

			final int dwarfOffset = nextDwarfOffset ++;
			final Register ghidraRegister = registers.getGhidraReg(dwarfOffset);

			if (ghidraRegister == null) {
				continue;
			}

			mapping.put(ghidraRegister.getOffset(), dwarfOffset);

			if (ghidraRegister.getOffset() == register.getOffset()) {
				return dwarfOffset;
			}

		}

		throw new RuntimeException("Unable to resolve DWARF identifier of register " + register.getName() + "!");

	}

}
