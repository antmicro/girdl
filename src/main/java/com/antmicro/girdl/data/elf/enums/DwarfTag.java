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
package com.antmicro.girdl.data.elf.enums;;

public class DwarfTag {

	public static final int ARRAY_TYPE = 0x01;
	public static final int CLASS_TYPE = 0x02;
	public static final int ENTRY_PO = 0x03;
	public static final int ENUMERATION_TYPE = 0x04;
	public static final int FORMAL_PARAMETER = 0x05;
	public static final int IMPORTED_DECLARATION = 0x08;
	public static final int LABEL = 0x0a;
	public static final int LEXICAL_BLOCK = 0x0b;
	public static final int MEMBER = 0x0d;
	public static final int POER_TYPE = 0x0f;
	public static final int REFERENCE_TYPE = 0x10;
	public static final int COMPILE_UNIT = 0x11;
	public static final int STRING_TYPE = 0x12;
	public static final int STRUCTURE_TYPE = 0x13;
	public static final int SUBROUTINE_TYPE = 0x15;
	public static final int TYPEDEF = 0x16;
	public static final int UNION_TYPE = 0x17;
	public static final int UNSPECIFIED_PARAMETERS = 0x18;
	public static final int VARIANT = 0x19;
	public static final int COMMON_BLOCK = 0x1a;
	public static final int COMMON_INCLUSION = 0x1b;
	public static final int INHERITANCE = 0x1c;
	public static final int INLINED_SUBROUTINE = 0x1d;
	public static final int MODULE = 0x1e;
	public static final int PTR_TO_MEMBER_TYPE = 0x1f;
	public static final int SET_TYPE = 0x20;
	public static final int SUBRANGE_TYPE = 0x21;
	public static final int WITH_STMT = 0x22;
	public static final int ACCESS_DECLARATION = 0x23;
	public static final int BASE_TYPE = 0x24;
	public static final int CATCH_BLOCK = 0x25;
	public static final int CONST_TYPE = 0x26;
	public static final int CONSTANT = 0x27;
	public static final int ENUMERATOR = 0x28;
	public static final int FILE_TYPE = 0x29;
	public static final int FRIEND = 0x2a;
	public static final int NAMELIST = 0x2b;
	public static final int NAMELIST_ITEM = 0x2c;
	public static final int PACKED_TYPE = 0x2d;
	public static final int SUBPROGRAM = 0x2e;
	public static final int TEMPLATE_TYPE_PARAMETER = 0x2f;
	public static final int TEMPLATE_VALUE_PARAMETER = 0x30;
	public static final int THROWN_TYPE = 0x31;
	public static final int TRY_BLOCK = 0x32;
	public static final int VARIANT_PART = 0x33;
	public static final int VARIABLE = 0x34;
	public static final int VOLATILE_TYPE = 0x35;
	public static final int DWARF_PROCEDURE = 0x36;
	public static final int RESTRICT_TYPE = 0x37;
	public static final int ERFACE_TYPE = 0x38;
	public static final int NAMESPACE = 0x39;
	public static final int IMPORTED_MODULE = 0x3a;
	public static final int UNSPECIFIED_TYPE = 0x3b;
	public static final int PARTIAL_UNIT = 0x3c;
	public static final int IMPORTED_UNIT = 0x3d;
	public static final int CONDITION = 0x3f;
	public static final int SHARED_TYPE = 0x40;
	public static final int TYPE_UNIT = 0x41;
	public static final int RVALUE_REFERENCE_TYPE = 0x42;
	public static final int TEMPLATE_ALIAS = 0x43;

	/*
	 * DWARF 5
	 */

	public static final int COARRAY_TYPE = 0x44;
	public static final int GENERIC_SUBRANGE = 0x45;
	public static final int DYNAMIC_TYPE = 0x46;
	public static final int ATOMIC_TYPE = 0x47;
	public static final int CALL_SITE = 0x48;
	public static final int CALL_SITE_PARAMETER = 0x49;
	public static final int SKELETON_UNIT = 0x4a;
	public static final int IMMUTABLE_TYPE = 0x4b;

}
