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

import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.SourceUnit;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

public class SymbolStream {

	private final String source;
	private final SourceUnit unit;

	private int line;
	private int column;
	private int index;

	private int tokenLine;
	private int tokenColumn;
	private int tokenIndex;

	private SymbolStream(String source, int line, int column, int index, SourceUnit unit) {
		this.source = source;
		this.line = line;
		this.column = column;
		this.index = index;
		this.unit = unit;

		// we track new line when a new character is advanced to,
		// but we never advance to the first character
		// so this is here to make sure the first character is not ignored by the stream
		if (this.index == 0 && !source.isEmpty()) {
			this.index = -1;
			this.column = 0;
			advance();
		}
	}

	public SymbolStream(String source, SourceUnit unit) {
		this(source, 1, 1, 0, unit);
	}

	private void assertNonEmpty() {
		if (isEmpty()) {
			ParseError.create(line, column, unit).setUnexpected("end of input").raise();
		}
	}

	@Override
	public String toString() {
		return "SymbolStream{line=" + line + ", column=" + column + ", index=" + index + ", next=" + SymbolPredicate.charToDescription(peek()) + "}";
	}

	/**
	 * Check if there are no symbols left in this stream
	 * if this returns true most methods in this class (e.g. accept(), except()) will throw when invoked.
	 */
	public boolean isEmpty() {
		return index >= source.length();
	}

	public void advance() {

		index ++;
		column ++;

		// end reached
		if (index >= source.length()) {
			return;
		}

		char c = source.charAt(index);

		// ignore carriage returns
		if (c == '\r') {
			advance();
		}

		// we set column to zero here as new-line is also treated as a valid symbol so it takes a
		// space, if we set it to 1 the first character in a line would be assigned to column 2
		// which is incorrect. This is not the cleanest solution, but it does work.
		if (c == '\n') {
			column = 0;
			line ++;
		}
	}

	/**
	 * Rewind all the way to token start, dropping all consumed symbols
	 * and erasing the token.
	 */
	public void rewind() {
		index = tokenIndex;
		column = tokenColumn;
		line = tokenLine;
	}

	/**
	 * Returns the number of characters consumed between now and the last beginToken() call,
	 * this is also the length of the lexeme of the current token.
	 */
	public int tokenLength() {
		return this.index - this.tokenIndex;
	}

	/**
	 * Create a new parse error build that points to the previous current character and line,
	 * this is a convenient alternative to calling getLine() and getColumn().
	 */
	public ParseError.Builder error() {
		return ParseError.create(line, column, unit);
	}

	public int getLine() {
		return line;
	}

	public int getColumn() {
		return column;
	}

	public char next() {
		char c = peek();
		advance();
		return c;
	}

	public char peek() {
		assertNonEmpty();
		return source.charAt(index);
	}

	public void expect(SymbolPredicate symbol) {
		char got = peek();

		if (!symbol.test(got)) {
			ParseError.create(line, column, unit).setExpected(symbol.description).setUnexpected(got).raise();
		}

		advance();
	}

	public boolean accept(SymbolPredicate symbol) {
		if (symbol.test(peek())) {
			advance();
			return true;
		}

		return false;
	}

	/**
	 * Asserts the next token to be the one given and advances the stream forward,
	 * otherwise throws a parse error.
	 */
	public void expect(char c) {
		expect(SymbolPredicate.of(c));
	}

	/**
	 * Checks if the next token matches the one given and advances the stream forward if it does,
	 * returns true if a character was consumed.
	 */
	public boolean accept(char c) {
		return accept(SymbolPredicate.of(c));
	}

	/**
	 * Returns a string of characters consumed
	 * between this call and the previous beginToken() call, the lexeme of the current token.
	 */
	public String getLexeme() {
		return source.substring(tokenIndex, index);
	}

	/**
	 * Begins tracking the next token, when getLexeme or endToken are called
	 * the token will encompass the characters consumed between that call and the previous beginToken() call.
	 */
	public void beginToken() {
		this.tokenLine = this.line;
		this.tokenColumn = this.column;
		this.tokenIndex = this.index;
	}

	/**
	 * Returns a token create from the characters consumed
	 * between this call and the previous beginToken() call.
	 */
	public Token endToken(TokenType type) {
		return endToken(lexeme -> type);
	}

	public Token endToken(Function<String, TokenType> mapper) {
		final String lexeme = getLexeme();
		return Token.create(lexeme, tokenLine, tokenColumn, unit, mapper.apply(lexeme));
	}

	/**
	 * Execute the given boolean provider and restore the stream
	 * to its prior state unless a true value is returned.
	 */
	public boolean boxed(BooleanSupplier lexer) {
		int line = this.line;
		int column = this.column;
		int index = this.index;

		if (!lexer.getAsBoolean()) {
			this.line = line;
			this.column = column;
			this.index = index;
			return false;
		}

		return true;
	}

	public boolean acceptString(String string) {
		return boxed(() -> {
			for (int i = 0; i < string.length(); i ++) {
				if (!accept(string.charAt(i))) {
					return false;
				}
			}

			return true;
		});
	}

	public boolean acceptAnyString(List<String> strings) {
		for (String string : strings) {
			if (acceptString(string)) {
				return true;
			}
		}

		return false;
	}

	public boolean hasNext() {
		return !isEmpty();
	}

}
