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

import com.antmicro.girdl.data.rdl.lexer.SymbolPredicate;
import com.antmicro.girdl.data.rdl.parser.TokenPredicate;

import java.util.List;
import java.util.stream.Collectors;

public final class ParseError extends RuntimeException {

	public final int line;
	public final int column;
	public final SourceUnit unit;
	private String causes = "";

	private ParseError(String message, Location location) {
		super(message);
		this.line = location.line;
		this.column = location.column;
		this.unit = location.unit;
	}

	@Deprecated
	public static Builder create(int line, int column, SourceUnit unit) {
		return new Builder().at(new Location(line, column, unit));
	}

	public static Builder create(Location location) {
		return new Builder().at(location);
	}

	@Override
	public String getMessage() {
		return super.getMessage() + " at line " + line + ":" + column + " in " + unit + causes;
	}

	public void append(String cause) {
		causes += "\n -> " + cause;
	}

	public static class Builder {

		private Location location;
		private String expected;
		private String unexpected;
		private String detail;
		private String after;

		public ParseError build() {
			StringBuilder builder = new StringBuilder();

			boolean prefixed = false;
			boolean showUnexpectedClause = true;

			if (detail != null) {
				if (unexpected != null) {
					builder.append(unexpected).append(" ").append(detail);
				} else {
					builder.append(detail);
				}

				showUnexpectedClause = false;
				prefixed = true;
			}

			if (expected != null) {
				builder.append(prefixed ? ", expected " : "Expected ").append(expected);
				prefixed = true;
			}

			if (unexpected != null && showUnexpectedClause) {
				builder.append(prefixed ? ", but got " : "Unexpected ").append(unexpected);
			}

			if (after != null) {
				builder.append(", after ").append(after);
			}

			return new ParseError(builder.toString(), location);
		}

		public Builder at(Location location) {
			this.location = location;
			return this;
		}

		public Builder setUnimplemented() {
			return setDetail("is currently unimplemented");
		}

		/**
		 * Alternative to the "expected" part, will be printed wth no prefix.
		 *
		 * @param detail Optional, null can be used if there is no detail.
		 */
		public Builder setDetail(String detail) {
			this.detail = detail;
			return this;
		}

		/**
		 * Sets the "unexpected X" path of the error message.
		 *
		 * @param token Optional, null can be used if there is no unexpected element.
		 */
		public Builder setUnexpected(Token token) {
			return token == null ? setUnexpected((String) null) : setUnexpected("token " + ParseUtil.quote(token.lexeme));
		}

		/**
		 * Sets the "expected X" path of the error message.
		 *
		 * @param predicate Optional, null can be used if there is no expected element.
		 */
		public Builder setExpected(TokenPredicate predicate) {
			return predicate == null ? setExpected((String) null) : setExpected(predicate.description.get());
		}

		public Builder setExpected(List<TokenPredicate> predicates) {

			if (predicates.isEmpty()) {
				return this;
			}

			if (predicates.size() == 1) {
				return setExpected(predicates.getFirst());
			}

			return setExpected(predicates.stream().map(TokenPredicate::getDescription).distinct().collect(Collectors.joining(", ")));
		}

		/**
		 * Sets the "expected X" path of the error message.
		 *
		 * @param symbol Optional, null can be used if there is no expected element.
		 */
		public Builder setExpected(SymbolPredicate symbol) {
			return symbol == null ? setExpected((String) null) : setExpected(symbol.description);
		}

		/**
		 * Sets the "unexpected X" path of the error message.
		 *
		 * @param unexpected The character that was not unexpected
		 */
		public Builder setUnexpected(char unexpected) {
			return setUnexpected(SymbolPredicate.charToDescription(unexpected));
		}

		/**
		 * Sets the "expected X" path of the error message.
		 *
		 * @param expected Optional, null can be used if there is no expected element.
		 */
		public Builder setExpected(String expected) {
			this.expected = expected;
			return this;
		}

		/**
		 * Sets the "unexpected X" path of the error message.
		 *
		 * @param unexpected Optional, null can be used if there is no unexpected element.
		 */
		public Builder setUnexpected(String unexpected) {
			this.unexpected = unexpected;
			return this;
		}

		/**
		 * Sets the "after X" path of the error message.
		 *
		 * @param after Optional, null can be used if there is no 'after' element.
		 */
		public Builder setAfter(String after) {
			this.after = after;
			return this;
		}

		/**
		 * Sets the "after X" path of the error message.
		 *
		 * @param token Optional, null can be used if there is no 'after' element.
		 */
		public Builder setAfter(Token token) {
			return token == null ? setAfter((String) null) : setAfter("token '" + token.lexeme + "'");
		}

		public void raise() {
			throw build();
		}

	}

}
