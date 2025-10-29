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
	private final Map<Integer, Integer> registerMappingCache = new HashMap<>();

	public DwarfRegistryResolver(Language language) {
		registers = Functional.except(() -> DWARFRegisterMappingsManager.getMappingForLang(language)).orElseThrow();
	}

	public int getDwarfRegister(Register register) {

		int targetGhidraOffset = register.getOffset();
		Integer dwarf = registerMappingCache.get(targetGhidraOffset);

		if (dwarf != null) {
			return dwarf;
		}

		// just an upper limit so that we can't fall into an infinite loop here
		// the number was chosen arbitrary, and needs to be larger or equal to the
		// largest register count of any supported instruction set
		for (int i = 0; i < 1000; i ++) {

			// we restart (see dwarfOffset and nextDwarfOffset) from the index of the
			// previously checked DWARF register and continue for UP TO this loop iteration
			// count, all found registers (including ones we were NOT looking for are cached).

			final int dwarfOffset = nextDwarfOffset ++;
			final Register ghidraRegister = registers.getGhidraReg(dwarfOffset);

			if (ghidraRegister == null) {
				continue;
			}

			// add found register to cache (even if this is not the one we were
			// looking for), this is needed as this loop will check each DWARF register only once.
			registerMappingCache.put(ghidraRegister.getOffset(), dwarfOffset);

			if (ghidraRegister.getOffset() == targetGhidraOffset) {
				return dwarfOffset;
			}

		}

		throw new RuntimeException("Unable to resolve DWARF identifier of Ghidra register " + register.getName() + "!");

	}

}
