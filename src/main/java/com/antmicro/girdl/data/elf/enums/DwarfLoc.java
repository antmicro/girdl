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

public class DwarfLoc {

	public static final int END_OF_LIST = 0x00;
	public static final int BASE_ADDRESSX = 0x01;
	public static final int STARTX_ENDX = 0x02;
	public static final int STARTX_LENGTH = 0x03;
	public static final int OFFSET_PAIR = 0x04;
	public static final int DEFAULT_LOCATION = 0x05;
	public static final int BASE_ADDRESS = 0x06;
	public static final int START_END = 0x07;
	public static final int START_LENGTH = 0x08;

}
