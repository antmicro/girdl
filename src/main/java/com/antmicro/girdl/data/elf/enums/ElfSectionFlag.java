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

public class ElfSectionFlag {

	public static final int NONE = 0;

	public static final int WRITE = 0x1;
	public static final int ALLOC = 0x2;
	public static final int EXECINSTR = 0x4;
	public static final int MERGE = 0x10;
	public static final int STRINGS = 0x20;
	public static final int INFO_LINK = 0x40;
	public static final int LINK_ORDER = 0x80;
	public static final int OS_NONCONFORMING = 0x100;
	public static final int GROUP = 0x200;
	public static final int TLS = 0x400;

}
