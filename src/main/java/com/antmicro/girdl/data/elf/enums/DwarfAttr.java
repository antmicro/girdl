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

public class DwarfAttr {

	public static final int SIBLING = 0x01;
	public static final int LOCATION = 0x02;
	public static final int NAME = 0x03;
	public static final int ORDERING = 0x09;
	public static final int BYTE_SIZE = 0x0b;
	public static final int BIT_SIZE = 0x0d;
	public static final int STMT_LIST = 0x10;
	public static final int LOW_PC = 0x11;
	public static final int HIGH_PC = 0x12;
	public static final int LANGUAGE = 0x13;
	public static final int DISCR = 0x15;
	public static final int DISCR_VALUE = 0x16;
	public static final int VISIBILITY = 0x17;
	public static final int IMPORT = 0x18;
	public static final int STRING_LENGTH = 0x19;
	public static final int COMMON_REFERENCE = 0x1a;
	public static final int COMP_DIR = 0x1b;
	public static final int CONST_VALUE = 0x1c;
	public static final int CONTAINING_TYPE = 0x1d;
	public static final int DEFAULT_VALUE = 0x1e;
	public static final int INLINE = 0x20;
	public static final int IS_OPTIONAL = 0x21;
	public static final int LOWER_BOUND = 0x22;
	public static final int PRODUCER = 0x25;
	public static final int PROTOTYPED = 0x27;
	public static final int RETURN_ADDR = 0x2a;
	public static final int START_SCOPE = 0x2c;
	public static final int BIT_STRIDE = 0x2e;
	public static final int UPPER_BOUND = 0x2f;
	public static final int ABSTRACT_ORIGIN = 0x31;
	public static final int ACCESSIBILITY = 0x32;
	public static final int ADDRESS_CLASS = 0x33;
	public static final int ARTIFICIAL = 0x34;
	public static final int BASE_TYPES = 0x35;
	public static final int CALLING_CONVENTION = 0x36;
	public static final int COUNT = 0x37;
	public static final int DATA_MEMBER_LOCATION = 0x38;
	public static final int DECL_COLUMN = 0x39;
	public static final int DECL_FILE = 0x3a;
	public static final int DECL_LINE = 0x3b;
	public static final int DECLARATION = 0x3c;
	public static final int DISCR_LIST = 0x3d;
	public static final int ENCODING = 0x3e;
	public static final int EXTERNAL = 0x3f;
	public static final int FRAME_BASE = 0x40;
	public static final int FRIEND = 0x41;
	public static final int IDENTIFIER_CASE = 0x42;
	public static final int NAMELIST_ITEM = 0x44;
	public static final int PRIORITY = 0x45;
	public static final int SEGMENT = 0x46;
	public static final int SPECIFICATION = 0x47;
	public static final int STATIC_LINK = 0x48;
	public static final int TYPE = 0x49;
	public static final int USE_LOCATION = 0x4a;
	public static final int VARIABLE_PARAMETER = 0x4b;
	public static final int VIRTUALITY = 0x4c;
	public static final int VTABLE_ELEM_LOCATION = 0x4d;
	public static final int ALLOCATED = 0x4e;
	public static final int ASSOCIATED = 0x4f;
	public static final int DATA_LOCATION = 0x50;
	public static final int BYTE_STRIDE = 0x51;
	public static final int ENTRY_PC = 0x52;
	public static final int USE_UTF8 = 0x53;
	public static final int EXTENSION = 0x54;
	public static final int RANGES = 0x55;
	public static final int TRAMPOLINE = 0x56;
	public static final int CALL_COLUMN = 0x57;
	public static final int CALL_FILE = 0x58;
	public static final int CALL_LINE = 0x59;
	public static final int DESCRIPTION = 0x5a;
	public static final int BINARY_SCALE = 0x5b;
	public static final int DECIMAL_SCALE = 0x5c;
	public static final int SMALL = 0x5d;
	public static final int DECIMAL_SIGN = 0x5e;
	public static final int DIGIT_COUNT = 0x5f;
	public static final int PICTURE_STRING = 0x60;
	public static final int MUTABLE = 0x61;
	public static final int THREADS_SCALED = 0x62;
	public static final int EXPLICIT = 0x63;
	public static final int OBJECT_POINTER = 0x64;
	public static final int ENDIANITY = 0x65;
	public static final int ELEMENTAL = 0x66;
	public static final int PURE = 0x67;
	public static final int RECURSIVE = 0x68;
	public static final int SIGNATURE = 0x69;
	public static final int MAIN_SUBPROGRAM = 0x6a;
	public static final int DATA_BIT_OFFSET = 0x6b;
	public static final int CONST_EXPR = 0x6c;
	public static final int ENUM_CLASS = 0x6d;
	public static final int LINKAGE_NAME = 0x6e;

	/*
	 * DWARF 5
	 */

	public static final int STRING_LENGTH_BIT_SIZE = 0x6f;
	public static final int STRING_LENGTH_BYTE_SIZE = 0x70;
	public static final int RANK = 0x71;
	public static final int STR_OFFSETS_BASE = 0x72;
	public static final int ADDR_BASE = 0x73;
	public static final int RNGLISTS_BASE = 0x74;
	public static final int DWO_NAME = 0x76;
	public static final int REFERENCE = 0x77;
	public static final int RVALUE_REFERENCE = 0x78;
	public static final int MACROS = 0x79;
	public static final int CALL_ALL_CALLS = 0x7a;
	public static final int CALL_ALL_SOURCE_CALLS = 0x7b;
	public static final int CALL_ALL_TAIL_CALLS = 0x7c;
	public static final int CALL_RETURN_PC = 0x7d;
	public static final int CALL_VALUE = 0x7e;
	public static final int CALL_ORIGIN = 0x7f;
	public static final int CALL_PARAMETER = 0x80;
	public static final int CALL_PC = 0x81;
	public static final int CALL_TAIL_CALL = 0x82;
	public static final int CALL_TARGET = 0x83;
	public static final int CALL_TARGET_CLOBBERED = 0x84;
	public static final int CALL_DATA_LOCATION = 0x85;
	public static final int CALL_DATA_VALUE = 0x86;
	public static final int NORETURN = 0x87;
	public static final int ALIGNMENT = 0x88;
	public static final int EXPORT_SYMBOLS = 0x89;
	public static final int DELETED = 0x8a;
	public static final int DEFAULTED = 0x8b;
	public static final int LOCLISTS_BASE = 0x8c;

}
