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

import com.antmicro.girdl.data.rdl.BinaryOperator;
import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.SourceUnit;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.UnaryOperator;
import com.antmicro.girdl.data.rdl.lexer.include.DummyIncluder;
import com.antmicro.girdl.data.rdl.lexer.include.IncludeResolver;
import com.antmicro.girdl.util.Functional;
import com.antmicro.girdl.util.file.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class Tokenizer {

	private final static SymbolPredicate HEX = new SymbolPredicate(c -> (c == 'x' || c == 'X'), "'x' or 'X'");
	private final static SymbolPredicate ESCAPE = new SymbolPredicate(c -> (c == '\\' || c == '"'), "valid string escape");
	private static final SymbolPredicate WHITE = new SymbolPredicate(Character::isWhitespace, "white space");
	private static final SymbolPredicate LETTER = new SymbolPredicate(ParseUtil::isLetterOrUnderscore, "letter");
	private static final SymbolPredicate ALPHANUMERIC = new SymbolPredicate(ParseUtil::isLetterOrDigit, "letter or digit");

	private static final SymbolPredicate DECIMAL = new SymbolPredicate(ParseUtil::isDecimalDigit, "decimal digit");
	private static final SymbolPredicate HEXADECIMAL = new SymbolPredicate(ParseUtil::isHexadecimalDigit, "hexadecimal digit");
	private static final SymbolPredicate BINARY = new SymbolPredicate(c -> (c == '0' || c == '1'), "binary digit");

	private final static Map<Character, SymbolPredicate> VERILOG_PREFIX = Map.of(
			'd', DECIMAL,
			'D', DECIMAL,
			'h', HEXADECIMAL,
			'H', HEXADECIMAL,
			'b', BINARY,
			'B', BINARY
	);

	private final static Set<String> RESERVED = Set.of(
			"default", "posedge", "negedge", "bothedge", "level", "nonsticky"
	);

	final Map<String, List<Token>> macros = new HashMap<>();
	IncludeResolver resolver = DummyIncluder.INSTANCE;

	private final static List<String> OPERATORS = Functional.mergedList(BinaryOperator.toLexemeList(), UnaryOperator.toLexemeList(), List.of("?"));
	private final static List<String> SYMBOLS = List.of("->", "::", "{", "}", "[", "]", "(", ")", ":", ";", "#", "'", ",", "=", "@", ".");

	Resource resolveIncludePath(Optional<Resource> resource, String path) {
		try {
			return resolver.resolve(resource, path);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void setIncludeResolver(IncludeResolver resolver) {
		this.resolver = resolver;
	}

	public void defineMacro(String name) {
		defineMacro(name, "");
	}

	public void defineMacro(String name, String value) {
		macros.put(name, tokenizeString(value, SourceUnit.ofString("value \"" + value + "\" of macro " + name)).tokens);
	}

	public TokenSink tokenizeFile(Resource resource) throws IOException {
		return tokenizeString(new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8), SourceUnit.ofResource(resource));
	}

	public TokenSink tokenizeString(String source, SourceUnit unit) {
		TokenSink sink = new TokenSink(this, new ArrayList<>());
		tokenize(sink, new SymbolStream(source, unit));
		return sink;
	}

	public TokenSink tokenizeString(String source) {
		return tokenizeString(source, SourceUnit.ofString("string " + ParseUtil.quote(source)));
	}

	private void scanMultiLineComment(SymbolStream stream) {
		while (stream.hasNext()) {
			if (stream.acceptString("*/")) {
				return;
			}

			stream.next();
		}

		stream.error().setExpected("*/").setUnexpected("end of input").raise();
	}

	private void scanSingleLineComment(SymbolStream stream) {
		while (stream.hasNext()) {
			if (stream.accept('\n')) {
				return;
			}

			stream.next();
		}
	}

	private Token scanString(SymbolStream stream) {
		while (true) {
			if (stream.accept('\\')) {
				stream.expect(ESCAPE);
				continue;
			}

			if (stream.accept('"')) {
				return stream.endToken(TokenType.STRING);
			}

			stream.next();
		}
	}

	private void scanDigits(SymbolStream stream, SymbolPredicate symbol) {

		// number must have at least one digit
		// and the first digit must not be as spacer (_)
		stream.expect(symbol);

		while (stream.hasNext()) {
			if (!stream.accept(HEXADECIMAL) && !stream.accept('_')) {
				break;
			}
		}

	}

	private void scanUntilNegated(SymbolStream stream, SymbolPredicate symbol) {
		while (stream.hasNext()) {
			char next = stream.peek();

			if (!symbol.test(next)) {
				break;
			}

			stream.advance();
		}
	}

	private Token scanNumber(SymbolStream stream) {

		stream.rewind();

		if (stream.boxed(() -> stream.accept('0') && stream.accept(HEX))) {
			scanDigits(stream, HEXADECIMAL);

			if (stream.tokenLength() <= 2) {
				stream.error().setUnexpected("end of number").setAfter(ParseUtil.quote(stream.getLexeme())).setExpected(HEXADECIMAL).raise();
			}

			return stream.endToken(TokenType.INTEGER);
		}

		scanDigits(stream, DECIMAL);

		// verilog style number
		if (stream.hasNext() && stream.accept('\'')) {

			char c = stream.peek();
			SymbolPredicate symbol = VERILOG_PREFIX.get(c);

			if (symbol == null) {
				String expected = VERILOG_PREFIX.keySet().stream().toList().stream().sorted().map(ParseUtil::quote).collect(Collectors.joining(", "));
				stream.error().setUnexpected(stream.peek()).setDetail("is not a valid verilog-style number prefix").setExpected(expected).setAfter(ParseUtil.quote(stream.getLexeme())).raise();
			}

			stream.advance();
			scanDigits(stream, symbol);
			return stream.endToken(TokenType.INTEGER);

		}

		return stream.endToken(TokenType.INTEGER);

	}

	private void tokenize(TokenSink sink, SymbolStream stream) {

		while (stream.hasNext()) {
			stream.beginToken();

			// escaped new line
			if (stream.acceptString("\\\n")) {
				sink.add(stream.endToken(TokenType.BREAK));
				continue;
			}

			if (stream.acceptString("/*")) {
				scanMultiLineComment(stream);
				continue;
			}

			if (stream.acceptString("//")) {
				scanSingleLineComment(stream);
				continue;
			}

			if (stream.accept(WHITE)) {
				continue;
			}

			if (stream.accept('`')) {
				scanUntilNegated(stream, ALPHANUMERIC);
				sink.add(stream.endToken(TokenType.DIRECTIVE));
				continue;
			}

			if (stream.accept('"')) {
				sink.add(scanString(stream));
				continue;
			}

			// escaped names can be used to avoid name clashes with keywords, this is still a normal identifier
			if (stream.accept('\\')) {
				stream.expect(LETTER);

				scanUntilNegated(stream, ALPHANUMERIC);
				sink.add(stream.endToken(TokenType.IDENTIFIER));
				continue;
			}

			// scan normal identifiers and keywords
			if (stream.accept(LETTER)) {
				scanUntilNegated(stream, ALPHANUMERIC);

				String lexeme = stream.getLexeme();

				// the reserved token is never check by type, only by lexeme
				// so it's only use is to not allow the lexemes added to RESERVED to pass as a IDENTIFIER
				if (RESERVED.contains(lexeme)) {
					sink.add(stream.endToken(TokenType.RESERVED));
					continue;
				}

				sink.add(stream.endToken(TokenType.IDENTIFIER));
				continue;
			}

			if (stream.accept(DECIMAL)) {
				sink.add(scanNumber(stream));
				continue;
			}

			if (stream.acceptAnyString(SYMBOLS)) {
				sink.add(stream.endToken(TokenType.SYMBOL));
				continue;
			}

			if (stream.acceptAnyString(OPERATORS)) {
				sink.add(stream.endToken(TokenType.OPERATOR));
				continue;
			}

			stream.error().setUnexpected(stream.peek()).setAfter(sink.tokens.isEmpty() ? null : sink.tokens.getLast()).raise();
		}

	}


}
