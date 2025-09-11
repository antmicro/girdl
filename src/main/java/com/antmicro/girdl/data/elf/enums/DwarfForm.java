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

public class DwarfForm {

	public static final int ADDR = 0x01;
	public static final int BLOCK2 = 0x03;
	public static final int BLOCK4 = 0x04;
	public static final int DATA2 = 0x05;
	public static final int DATA4 = 0x06;
	public static final int DATA8 = 0x07;
	public static final int STRING = 0x08;
	public static final int BLOCK = 0x09;
	public static final int BLOCK1 = 0x0a;
	public static final int DATA1 = 0x0b;
	public static final int FLAG = 0x0c;
	public static final int SDATA = 0x0d;
	public static final int STRP = 0x0e;
	public static final int UDATA = 0x0f;
	public static final int REF_ADDR = 0x10;
	public static final int REF1 = 0x11;
	public static final int REF2 = 0x12;
	public static final int REF4 = 0x13;
	public static final int REF8 = 0x14;
	public static final int REF_UDATA = 0x15;
	public static final int INDIRECT = 0x16;
	public static final int SEC_OFFSET = 0x17;
	public static final int EXPRLOC = 0x18;
	public static final int FLAG_PRESENT = 0x19;

	/*
	 * DWARF 5
	 */

	public static final int STRX = 0x1a;
	public static final int ADDRX = 0x1b;
	public static final int REF_SUP4 = 0x1c;
	public static final int STRP_SUP = 0x1d;
	public static final int DATA16 = 0x1e;
	public static final int LINE_STRP = 0x1f;
	public static final int REF_SIG8 = 0x20;
	public static final int IMPLICIT_CONST = 0x21;
	public static final int LOCLISTX = 0x22;
	public static final int RNGLISTX = 0x23;
	public static final int REF_SUP8 = 0x24;
	public static final int STRX1 = 0x25;
	public static final int STRX2 = 0x26;
	public static final int STRX3 = 0x27;
	public static final int STRX4 = 0x28;
	public static final int ADDRX1 = 0x29;
	public static final int ADDRX2 = 0x2a;
	public static final int ADDRX3 = 0x2b;
	public static final int ADDRX4 = 0x2c;

}
