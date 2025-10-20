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

public class DwarfLine {

	// standard opcodes
	public static final int COPY = 0x01;
	public static final int ADVANCE_PC = 0x02;
	public static final int ADVANCE_LINE = 0x03;
	public static final int SET_FILE = 0x04;
	public static final int SET_COLUMN = 0x05;
	public static final int NEGATE_STMT = 0x06;
	public static final int SET_BASIC_BLOCK = 0x07;
	public static final int CONST_ADD_PC = 0x08;
	public static final int FIXED_ADVANCE_PC = 0x09;
	public static final int SET_PROLOGUE_END = 0x0a;
	public static final int SET_EPILOGUE_BEGIN = 0x0b;
	public static final int SET_ISA = 0x0c;

	// extended opcodes
	public static final int EXT_BEGIN = 0x00;
	public static final int EXT_END_SEQUENCE = 0x01;
	public static final int EXT_SET_ADDRESS = 0x02;

}
