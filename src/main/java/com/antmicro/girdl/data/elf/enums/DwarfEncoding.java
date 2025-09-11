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

public class DwarfEncoding {

	public static final int ADDRESS = 0x01;
	public static final int BOOLEAN = 0x02;
	public static final int COMPLEX_FLOAT = 0x03;
	public static final int FLOAT = 0x04;
	public static final int SIGNED = 0x05;
	public static final int SIGNED_CHAR = 0x06;
	public static final int UNSIGNED = 0x07;
	public static final int UNSIGNED_CHAR = 0x08;
	public static final int IMAGINARY_FLOAT = 0x09;
	public static final int PACKED_DECIMAL = 0x0a;
	public static final int NUMERIC_STRING = 0x0b;
	public static final int EDITED = 0x0c;
	public static final int SIGNED_FIXED = 0x0d;
	public static final int UNSIGNED_FIXED = 0x0e;
	public static final int DECIMAL_FLOAT = 0x0f;
	public static final int UTF = 0x10;

	/*
	 * DWARF 5
	 */

	public static final int UCS = 0x11;
	public static final int ASCII = 0x12;

}
