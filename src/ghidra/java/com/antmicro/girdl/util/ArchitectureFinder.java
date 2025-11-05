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

import com.antmicro.girdl.data.elf.enums.ElfMachine;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class ArchitectureFinder {

	private static final Lazy<Map<String, Integer>> LOOKUP = new Lazy<>();

	private static Map<String, Integer> createMachineMap() {
		Map<String, Integer> map = new HashMap<>();

		map.put("x86", ElfMachine.I386);
		map.put("x86:64", ElfMachine.X86_64);
		map.put("i386", ElfMachine.I386);
		map.put("i860", ElfMachine.I860);
		map.put("powerpc", ElfMachine.PPC);
		map.put("powerpc:64", ElfMachine.PPC64);
		map.put("sparc", ElfMachine.SPARC);
		map.put("sparc:64", ElfMachine.SPARCV9);
		map.put("arm", ElfMachine.ARM);
		map.put("arm:64", ElfMachine.AARCH64);
		map.put("aarch64", ElfMachine.AARCH64);
		map.put("z80", ElfMachine.Z80);
		map.put("riscv", ElfMachine.RISCV);
		map.put("risc-v", ElfMachine.RISCV);

		return map;
	}

	private static Map<String, Integer> getMachineMap() {
		return LOOKUP.get(ArchitectureFinder::createMachineMap);
	}

	public static /* ElfMachine */ int guessElfMachine(Program program, /* ElfMachine */ int fallback) {
		final String machine = program.getLanguage().getProcessor().toString().toLowerCase(Locale.ROOT);
		final Map<String, Integer> map = getMachineMap();

		// first look for "arch:bits", if that fails try just "arch" and if that fails too return the fallback machine
		int type = map.getOrDefault(machine + ":" + program.getDefaultPointerSize() * 8, map.getOrDefault(machine, fallback));

		Msg.info(ArchitectureFinder.class, "Guessed processor '" + program.getLanguage().getLanguageID() + "' to be ELF machine " + Reflect.constValueName(ElfMachine.class, type));
		return type;
	}

}
