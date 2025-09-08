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

import com.antmicro.girdl.data.rdl.compiler.Scope;

import java.util.ArrayList;
import java.util.List;

/**
 * Used for special specification defined keyword-values.
 */
public class SymbolicType extends TypeValue {

	private static final List<SymbolicType> TYPES = new ArrayList<>();

	public static final SymbolicType ACCESS = new SymbolicType("accesstype", "na", "rw", "wr", "r", "w", "rw1", "w1");
	public static final SymbolicType ON_READ = new SymbolicType("onreadtype", "rclr", "rset", "ruser");
	public static final SymbolicType ON_WRITE = new SymbolicType("onwritetype", "woset", "woclr", "wot", "wzs", "wzc", "zt", "wclr", "wset", "wuser");
	public static final SymbolicType ADDRESSING = new SymbolicType("addressingtype", "compact", "regalign", "fullalign");
	public static final SymbolicType PRECEDENCE = new SymbolicType("precedencetype", "hw", "sw");

	private final List<String> words;

	private SymbolicType(String name, String... words) {
		super(name);
		this.words = List.of(words);
		TYPES.add(this);
	}

	@Override
	public Value instantiate(Scope scope, Value rhs) {

		if (rhs.getType() == this) {
			return rhs;
		}

		if (rhs.getType() != PrimitiveType.UNSET) {
			throw new RuntimeException("Unable to implicitly cast " + rhs.toString() + " to type " + name);
		}

		return new Instance(this, 0);
	}

	public static Value parseOrNull(String string) {

		for (SymbolicType type : TYPES) {
			for (int i = 0; i < type.words.size(); i ++) {
				String word = type.words.get(i);

				if (word.equals(string)) {
					return new Instance(type, i);
				}
			}
		}

		return null;
	}

	public static class Instance extends TypedValue<SymbolicType> {

		public final int index;

		public Instance(SymbolicType type, int index) {
			super(type);
			this.index = index;
		}

		public String getSymbol() {
			return type.words.get(index);
		}

		@Override
		public String toString() {
			return getSymbol();
		}

	}

}
