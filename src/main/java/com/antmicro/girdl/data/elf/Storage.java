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

	public static final Storage UNKNOWN = new Storage(Type.UNKNOWN, 0);

	public enum Type {
		REGISTER(true),
		STACK(true),
		ADDRESS(true),
		CONST(false),
		UNKNOWN(false);

		private final boolean located;

		Type(boolean located) {
			this.located = located;
		}

		public boolean hasLocation() {
			return located;
		}
	}

	final Type type;
	final long offset;

	private Storage(Type type, long offset) {
		this.type = type;
		this.offset = offset;
	}

	public boolean isKnown() {
		return type != Type.UNKNOWN;
	}

	public static Storage ofAddress(long offset) {
		return new Storage(Type.ADDRESS, offset);
	}

	public static Storage ofStack(long offset) {
		return new Storage(Type.STACK, offset);
	}

	public static Storage ofRegister(long offset) {
		return new Storage(Type.REGISTER, offset);
	}

	public static Storage ofConst(long offset) {
		return new Storage(Type.CONST, offset);
	}

}
