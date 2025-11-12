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

import java.util.Optional;

public class DwarfOp {

	public static final int ADDR = 0x03; // 1 op, constant address (size is target specific)
	public static final int DEREF = 0x06; // 0 ops
	public static final int CONST1U = 0x08; // 1 op, 1-byte constant
	public static final int CONST1S = 0x09; // 1 op, 1-byte constant
	public static final int CONST2U = 0x0a; // 1 op, 2-byte constant
	public static final int CONST2S = 0x0b; // 1 op, 2-byte constant
	public static final int CONST4U = 0x0c; // 1 op, 4-byte constant
	public static final int CONST4S = 0x0d; // 1 op, 4-byte constant
	public static final int CONST8U = 0x0e; // 1 op, 8-byte constant
	public static final int CONST8S = 0x0f; // 1 op, 8-byte constant
	public static final int CONSTU = 0x10; // 1 op, ULEB128 constant
	public static final int CONSTS = 0x11; // 1 op, SLEB128 constant
	public static final int DUP = 0x12; // 0 ops
	public static final int DROP = 0x13; // 0 ops
	public static final int OVER = 0x14; // 0 ops
	public static final int PICK = 0x15; // 1 op, 1-byte stack index
	public static final int SWAP = 0x16; // 0 ops

	public static final int ROT = 0x17; // 0 ops
	public static final int XDEREF = 0x18; // 0 ops
	public static final int ABS = 0x19; // 0 ops
	public static final int AND = 0x1a; // 0 ops
	public static final int DIV = 0x1b; // 0 ops
	public static final int MINUS = 0x1c; // 0 ops
	public static final int MOD = 0X1D; // 0 ops
	public static final int MUL = 0X1E; // 0 ops
	public static final int NEG = 0X1F; // 0 ops
	public static final int NOT = 0X20; // 0 ops
	public static final int OR = 0X21; // 0 ops
	public static final int PLUS = 0X22; // 0 ops
	public static final int PLUS_UCONST = 0x23; // 1 op, ULEB128 addend
	public static final int SHL = 0X24; // 0 ops
	public static final int SHR = 0X25; // 0 ops
	public static final int SHRA = 0X26; // 0 ops
	public static final int XOR = 0X27; // 0 ops
	public static final int BRA = 0X28; // 1 op, signed 2-byte constant
	public static final int EQ = 0X29; // 0 ops
	public static final int GE = 0X2A; // 0 ops
	public static final int GT = 0X2B; // 0 ops
	public static final int LE = 0X2C; // 0 ops
	public static final int LT = 0X2D; // 0 ops
	public static final int NE = 0x2e; // 0 ops
	public static final int SKIP = 0x2f; // 1 op, signed 2-byte constant

	public static final int LIT0 = 0x30;
	public static final int LIT31 = 0x4f;

	public static final int REG0 = 0x50; // 0 ops
	public static final int REG31 = 0x6f; // 0 ops
	public static final int BREG0 = 0x70; // 1 op, SLEB128 offset
	public static final int BREG31 = 0x8f; // 0 ops
	public static final int REGX = 0x90; // 1 op, ULEB128 register
	public static final int FBREG = 0x91; // 1 op, SLEB128 offset
	public static final int BREGX = 0x92; // 2 ops, ULEB128 register, SLEB128 offset
	public static final int PIECE = 0x93; // 1 op, ULEB128 size of piece
	public static final int DEREF_SIZE = 0x94; // 1 op, 1-byte size of data retrieved
	public static final int XDEREF_SIZE = 0x95; // 1 op, 1-byte size of data retrieved
	public static final int NOP = 0x96; // 0 ops
	public static final int PUSH_OBJECT_ADDRESS = 0x97; // 0 ops
	public static final int CALL2 = 0x98; // 1 op, 2-byte offset of DIE
	public static final int CALL4 = 0x99; // 1 op, 4-byte offset of DIE
	public static final int CALL_REF = 0x9a; // 1 op, 4- or 8-byte offset of DIE
	public static final int FORM_TLS_ADDRESS = 0x9b; // 0 ops
	public static final int CALL_FRAME_CFA = 0x9c; // 0 ops
	public static final int BIT_PIECE = 0x9d; // 2 ops, ULEB128 size, ULEB128 offset
	public static final int IMPLICIT_VALUE = 0x9e; // 2 ops, ULEB128 size, block of that size
	public static final int STACK_VALUE = 0x9f; // 0 ops

	/*
	 * DWARF 5
	 */

	public static final int IMPLICIT_POINTER = 0xa0; // 2 ops, 4- or 8-byte offset of DIE, SLEB128 constant offset
	public static final int ADDRX = 0xa1; // 1 op, ULEB128 indirect address
	public static final int CONSTX = 0xa2; // 1 op, ULEB128 indirect constant
	public static final int ENTRY_VALUE = 0xa3; // 2 ops, ULEB128 size, block of that size
	public static final int CONST_TYPE = 0xa4; // 3 ops, ULEB128 type entry offset, 1-byte size, constant value
	public static final int REGVAL_TYPE = 0xa5; // 2 ops, ULEB128 register number, ULEB128 constant offset
	public static final int DEREF_TYPE = 0xa6; // 2 ops, 1-byte size, ULEB128 type entry offset
	public static final int XDEREF_TYPE = 0xa7; // 2 ops, 1-byte size, ULEB128 type entry offset
	public static final int CONVERT = 0xa8; // 1 ops, ULEB128 type entry offset
	public static final int REINTERPRET = 0xa9; // 1 ops, ULEB128 type entry offset

	/*
	 * Helpers
	 */

	public static Optional<Long> register(long registerNumber) {
		final long opcode = REG0 + registerNumber;
		return opcode > REG31 ? Optional.empty() : Optional.of(opcode);
	}

	public static Optional<Long> literal(long literalNumber) {
		final long opcode = LIT0 + literalNumber;
		return opcode > LIT31 ? Optional.empty() : Optional.of(opcode);
	}

}
