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
package com.antmicro.girdl.data.rdl.lexer;

import java.util.function.Predicate;
import java.util.stream.IntStream;

public class SymbolPredicate implements Predicate<Character> {

	private static final SymbolPredicate[] CACHE = IntStream.range(0, 127).mapToObj(i -> new SymbolPredicate((char) i)).toArray(SymbolPredicate[]::new);

	private final Predicate<Character> predicate;
	public final String description;

	public SymbolPredicate(Predicate<Character> predicate, String description) {
		this.predicate = predicate;
		this.description = description;
	}

	public SymbolPredicate(char c) {
		this.predicate = got -> got == c;
		this.description = charToDescription(c);
	}

	public static String charToDescription(char c) {
		if (c == '\0') return "null byte character";
		if (c == '\n') return "new line character";
		if (c == '\t') return "horizontal tab character";
		if (c == '\r') return "carriage return character";

		if (c < ' ') return "ASCII 0x" + Integer.toHexString(c);
		if (c > '~') return "non-ASCII character 0x" + Integer.toHexString(c);

		return "'" + c + "'";
	}

	public static SymbolPredicate of(char c) {
		return c < 127 ? CACHE[c] : new SymbolPredicate(c);
	}

	@Override
	public String toString() {
		return description;
	}

	@Override
	public boolean test(Character character) {
		return predicate.test(character);
	}

}
