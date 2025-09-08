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

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.SourceUnit;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

public class TokenStream {

	protected final List<Token> tokens;
	protected final List<TokenPredicate> mismatches = new ArrayList<>();

	protected final String name;
	protected final int start;
	protected final int end;

	protected int index;

	public TokenStream(List<Token> tokens, int start, int end, int index, String name) {
		this.tokens = tokens;
		this.start = start;
		this.end = end;
		this.index = index;
		this.name = name;
	}

	public TokenStream(List<Token> tokens, int start, int end, String name) {
		this.tokens = tokens;
		this.start = Math.max(0, start);
		this.end = Math.min(tokens.size(), end);
		this.index = this.start;
		this.name = name;
	}

	@Override
	public String toString() {
		return "TokenStream{start=" + start + ", end=" + end + ", index=" + index + ", next=" + peek().toShortString() + "}";
	}

	public TokenStream(List<Token> tokens) {
		this(tokens, 0, tokens.size(), "input");
	}

	/**
	 * Mostly a debugging method, returns list of all remaining tokens that belong to
	 * the stream by copying the underlying token list.
	 */
	public List<Token> toList() {
		List<Token> remaining = new ArrayList<>();

		for (int i = index; i < end; i ++) {
			remaining.add(tokens.get(i));
		}

		return remaining;
	}

	public Token obtainPreviousToken() {

		// simplest case, out token was just matched
		if ((index - 1) < end && (index - 1) >= start) return tokens.get(index - 1);

		// we run out of tokens but the stream was not empty so just get the previous token
		if (end - 1 >= start) return tokens.get(end - 1);

		// the stream was empty, but was just a substream of a larger stream
		if (end - 1 >= 0) return tokens.get(end - 1);

		// just to be sure we didn't mess up the ranges, go by the underlying list itself
		if (!tokens.isEmpty()) tokens.getFirst();

		// there really were no tokens
		throw ParseError.create(1, 1, SourceUnit.UNKNOWN).setUnexpected("end of " + name).build();

 	}

	private void assertNonEmpty(TokenPredicate predicate) {
		if (isEmpty()) {
			if (predicate != null) {
				mismatches.add(predicate);
			}

			obtainPreviousToken().error().setUnexpected("end of " + name).setExpected(mismatches).raise();
			mismatches.clear();
		}
	}

	public void assertEmpty() {
		if (hasNext()) {
			TokenPredicate terminal = TokenPredicate.ofTerminal(name);
			mismatches.add(terminal);

			peek().error().setExpected(mismatches).raise();
		}
	}

	public boolean isEmpty() {
		return index >= end;
	}

	public void startFresh() {
		mismatches.clear();
	}

	public boolean hasNext() {
		return !isEmpty();
	}

	public Token peek() {
		assertNonEmpty(null);
		return tokens.get(index);
	}

	public Location here() {
		return peek();
	}

	public Optional<Location> optionalLocation() {
		if (isEmpty()) {
			return Optional.empty();
		}

		return Optional.of(here());
	}

	public Token next() {
		Token token = peek();
		advance();
		return token;
	}

	public void advance() {
		if (index < end) {
			index ++;
			return;
		}

		index = end;
	}

	public boolean match(TokenType type) {
		return match(TokenPredicate.of(type));
	}

	public boolean match(String lexeme) {

		if (isEmpty()) {
			return false;
		}

		return match(TokenPredicate.of(lexeme));
	}

	public boolean match(TokenPredicate predicate) {
		return accept(predicate).isPresent();
	}

	public Optional<Token> accept(TokenType type) {
		return accept(TokenPredicate.of(type));
	}

	public Optional<Token> accept(String lexeme) {
		return accept(TokenPredicate.of(lexeme));
	}

	private Optional<Token> accept(TokenPredicate predicate) {
		assertNonEmpty(predicate);
		Token token = peek();

		if (predicate.test(token)) {
			advance();
			mismatches.clear();
			return Optional.of(token);
		}

		mismatches.add(predicate);
		return Optional.empty();
	}

	public Token expect(TokenType type) {
		return expect(TokenPredicate.of(type));
	}

	public Token expect(String lexeme) {
		return expect(TokenPredicate.of(lexeme));
	}

	private Token expect(TokenPredicate predicate) {
		assertNonEmpty(predicate);
		Token token = peek();

		if (predicate.test(token)) {
			advance();
			mismatches.clear();
			return token;
		}

		throw token.error().setExpected(predicate.description.get()).build();
	}

	public ParseError syntaxError() {
		return peek().error().setExpected(mismatches).build();
	}

	public boolean lookahead(Predicate<TokenStream> predicate) {
		int previous = index;
		boolean matched = false;

		try {
			if (predicate.test(this)) {
				matched = true;
			}
		} catch (ParseError ignored) {}

		this.index = previous;
		return matched;
	}

	public PaddedTokenStream until(String lexeme, String name) {

		TokenPredicate predicate = TokenPredicate.of(lexeme);
		int begin = index;

		while (hasNext()) {

			if (match(predicate)) {
				break;
			}

			next();

		}

		return new PaddedTokenStream(tokens, begin, index, name);
	}

	/**
	 * Returns a sub-stream of all the tokens that fall between the current token and the end of line
	 * with support for line-end-escape (TokenType.BREAK) (\\n) line extension.
	 *
	 * @param name The name for the returned sub-stream=
	 */
	public TokenStream untilNextLine(String name) {

		// avoid throwing if the stream is empty
		if (isEmpty()) {
			return new TokenStream(tokens, index, index, name);
		}

		int previous = index - 1;
		int begin = index;
		int line = previous > start ? tokens.get(previous).line : peek().line;

		boolean expectNewLine = false;

		while (hasNext()) {

			if (!expectNewLine && match(TokenType.BREAK)) {
				expectNewLine = true;
				continue;
			}

			Token token = peek();

			if (token.line != line) {
				if (expectNewLine) {
					expectNewLine = false;
					line = token.line;
					continue;
				}

				break;
			}

			// realistically shouldn't happen as the TokenType.BREAK is only emitted at the ends of lines
			if (expectNewLine) {
				token.error().setExpected("end of line");
			}

			next();
		}

		return new TokenStream(tokens, begin, index, name);
	}

	/**
	 * Returns a sub-stream of all the tokens that fall into the given block
	 * as defined by the template string. The template string must consist of exactly two characters,
	 * first if the opening token, the second the closing token.
	 *
	 * @apiNote The block() expects the first opening bracket to already have been consumed! That is you should have
	 * manually called either expect() or accept() before calling block()!
	 *
	 * @implNote Note that the way tokens are specified to block() precludes block() from
	 * operating on multi-character tokens.
	 *
	 * @param template The block template for the open and close tokens
	 * @param name The name for the returned sub-stream
	 */
	public TokenStream block(String template, String name) {

		if (template.length() != 2) {
			throw new RuntimeException("Invalid block template \"" + template + "\", templates must be 2 character long");
		}

		TokenPredicate open = TokenPredicate.of(template.charAt(0));
		TokenPredicate close = TokenPredicate.of(template.charAt(1));

		int begin = index;
		int depth = 1;

		while (depth != 0) {

			if (match(close)) {
				depth--;
				continue;
			}

			if (match(open)) {
				depth++;
				continue;
			}

			next();
		}

		// we subtract one to drop the last closing bracket from the stream
		return new TokenStream(tokens, begin, index - 1, name);
	}

}
