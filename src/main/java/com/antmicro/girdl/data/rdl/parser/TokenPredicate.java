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
package com.antmicro.girdl.data.rdl.parser;

import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;

import java.util.Locale;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.function.Supplier;

public class TokenPredicate implements Predicate<Token> {

	private final Predicate<Token> predicate;
	public final Supplier<String> description;

	public TokenPredicate(Predicate<Token> predicate, Supplier<String> description) {
		this.predicate = predicate;
		this.description = description;
	}

	public static TokenPredicate of(TokenType type) {
		return new TokenPredicate(token -> token.type == type, () -> type.name().toLowerCase(Locale.ROOT));
	}

	public static TokenPredicate of(String lexeme) {
		return new TokenPredicate(token -> Objects.equals(token.lexeme, lexeme), () -> ParseUtil.quote(lexeme));
	}

	public static TokenPredicate of(char lexeme) {
		return new TokenPredicate(token -> token.lexeme.length() == 1 && token.lexeme.charAt(0) == lexeme, () -> ParseUtil.quote("" + lexeme));
	}

	public static TokenPredicate ofTerminal(String name) {
		return new TokenPredicate(token -> false, () -> "end of " + name);
	}

	@Override
	public String toString() {
		return description.get();
	}

	@Override
	public boolean test(Token token) {
		return predicate.test(token);
	}

	public String getDescription() {
		return description.get();
	}

}
