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
package com.antmicro.girdl.data.elf;

public class Storage {

	public enum Type {
		REGISTER,
		STACK,
		CONST,
		UNKNOWN
	}

	final Type type;
	final long offset;
	final int size;

	public Storage(Type type, long offset, int size) {
		this.type = type;
		this.offset = offset;
		this.size = size;
	}

	public static Storage ofUnknown(int bytes) {
		return new Storage(Type.UNKNOWN, 0, bytes);
	}

	public boolean isKnown() {
		return type != Type.UNKNOWN;
	}

}
