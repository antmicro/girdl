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
package com.antmicro.girdl.data.elf.enums;

public class ElfSectionType {

	public static final int NULL = 0;
	public static final int PROGBITS = 1;
	public static final int SYMTAB = 2;
	public static final int STRTAB = 3;
	public static final int RELA = 4;
	public static final int HASH = 5;
	public static final int DYNAMIC = 6;
	public static final int NOTE = 7;
	public static final int NOBITS = 8;
	public static final int REL = 9;
	public static final int SHLIB = 10;
	public static final int DYNSYM = 11;

}
