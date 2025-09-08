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
package com.antmicro.girdl.data.rdl.compiler.model;

public abstract class PrimitiveValue extends TypedValue<PrimitiveType> {

	protected PrimitiveValue(PrimitiveType type) {
		super(type);
	}

	/**
	 * Integer values of any length (RDL's longint) the Verilog specification defines "longint" as
	 * 64-bit signed integer so exactly the same as Java's long, the "unsinged" variant is also handled by this value.
	 */
	public static final class IntValue extends PrimitiveValue {

		public final long value;

		private IntValue(long value) {
			super(PrimitiveType.INTEGER);
			this.value = value;
		}

		public static IntValue of(long value) {
			return new IntValue(value);
		}

		// construct default IntValue
		public static IntValue create() {
			return new IntValue(0);
		}

		public long toLong() {
			return value;
		}

		public String toString() {
			return String.valueOf(value);
		}

	}

	/**
	 * Implements the variable-width bit type, with support for up-to 64 bits.
	 */
	public static final class BitValue extends PrimitiveValue {

		public final long width;
		public final long value;

		private BitValue(long value, long width) {
			super(PrimitiveType.BIT);
			this.value = value;
			this.width = width;
		}

		public static BitValue of(long value, long width) {
			return new BitValue(value, width);
		}

		// construct default IntValue
		public static BitValue create() {
			return new BitValue(0, 1);
		}

		public long toLong() {
			return value;
		}

		public String toString() {
			return width + "'" + value;
		}

	}

	public static final class BoolValue extends PrimitiveValue {

		public static final BoolValue TRUE = new BoolValue(true);
		public static final BoolValue FALSE = new BoolValue(false);

		public final boolean value;

		private BoolValue(boolean value) {
			super(PrimitiveType.BOOL);
			this.value = value;
		}

		public static BoolValue of(boolean flag) {
			return flag ? TRUE : FALSE;
		}

		// construct default BoolValue
		public static BoolValue create() {
			return FALSE;
		}

		public long toLong() {
			return value ? 1L : 0L;
		}

		public String toString() {
			return String.valueOf(value);
		}

		public BoolValue negate() {
			return of(!value);
		}

	}

	public static final class TextValue extends PrimitiveValue {

		public static final TextValue EMPTY = new TextValue("");

		public final String value;

		private TextValue(String value) {
			super(PrimitiveType.STRING);
			this.value = value;
		}

		public static TextValue of(String string) {
			return new TextValue(string);
		}

		// construct default StringValue
		public static TextValue create() {
			return EMPTY;
		}

		public long toLong() {
			return Long.decode(value);
		}

		public String toString() {
			return String.valueOf(value);
		}

	}

}
