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
package com.antmicro.girdl.data.rdl;

import java.util.function.Function;

public final class Token extends Location {

	public final String lexeme;
	public final TokenType type;
	private Object parsed;

	private Token(String lexeme, int line, int column, SourceUnit unit, TokenType type) {
		super(line, column, unit);

		this.lexeme = lexeme;
		this.type = type;
	}

	private Token bind(Function<Token, Object> mapper) {
		this.parsed = mapper.apply(this);
		return this;
	}

	public static Token create(String lexeme, int line, int column, SourceUnit unit, TokenType type) {
		return new Token(lexeme, line, column, unit, type).bind(type.getPostProcessor());
	}

	@Override
	public String toString() {
		return type.name() + ": " + lexeme + " at " + where();
	}

	public long asLong() {
		if (parsed instanceof Long boxed) {
			return boxed;
		}

		throw getAttachmentTypeError("long");
	}

	public String asString() {
		if (parsed instanceof String string) {
			return string;
		}

		throw getAttachmentTypeError("string");
	}

	public ParseError.Builder error() {
		return ParseError.create(this).setUnexpected(this);
	}

	private RuntimeException getAttachmentTypeError(String what) {
		throw new RuntimeException("Unable to convert token of type " + type.name() + " to a " + what + " value, caused for token '" + lexeme + "' at " + where());
	}

	public String toShortString() {
		return "{type=" + type + ", lexeme=" + ParseUtil.quote(lexeme) + "}";
	}

	public Token withLineOffset(int offset) {
		if (offset == 0) {
			return this;
		}

		return new Token(lexeme, line + offset, column, unit, type).bind(that -> parsed);
	}

}
