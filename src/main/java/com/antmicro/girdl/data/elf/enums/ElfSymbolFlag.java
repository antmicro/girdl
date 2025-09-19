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

public class ElfSymbolFlag {

	public static final int NOTYPE = 0;
	public static final int OBJECT = 1;
	public static final int FUNC = 2;
	public static final int SECTION = 3;
	public static final int FILE = 4;

	// biding
	public static final int LOCAL = 0 << 4; // we don't support using this binding, see sh_info specification
	public static final int GLOBAL = 1 << 4;
	public static final int WEAK = 2 << 4;

}
