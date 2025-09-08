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

import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.util.UnimplementedException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;

public class TokenSink {

	private final Tokenizer tokenizer;
	public List<Token> tokens;
	private final Stack<Branch> stack = new Stack<>();

	private int lineOffset = 0;

	final Map<String, List<Token>> macros;

	public TokenSink(Tokenizer tokenizer, List<Token> tokens) {
		this.tokenizer = tokenizer;
		this.tokens = tokens;

		// copy user defined macros before we start preprocessing
		this.macros = new HashMap<>(tokenizer.macros);
	}

	public TokenSink preprocess() {
		List<Token> after = new ArrayList<>(tokens.size());
		TokenStream stream = asTokenStream();

		preprocess(after, stream);

		return new TokenSink(tokenizer, after);
	}

	public TokenStream asTokenStream() {
		return new TokenStream(tokens);
	}

	public void add(Token token) {
		tokens.add(token);
	}

	private void pushBranchDirective(boolean condition) {
		stack.push(new Branch(condition, null));
	}

	private void popBranchDirective() {
		stack.pop();
	}

	private void chainBranchDirective(boolean condition) {
		stack.push(new Branch(condition, stack.pop()));
	}

	private void substituteMacro(List<Token> output, Token macro) {
		String name = macro.asString();

		if ("__LINE__".equals(name)) {
			output.add(Token.create(String.valueOf(macro.line + lineOffset), macro.line + lineOffset, macro.column, macro.unit, TokenType.INTEGER));
			return;
		}

		List<Token> substitution = macros.get(name);

		if (substitution == null) {
			throw macro.error().setUnexpected("Undefined macro " + ParseUtil.quote(macro.lexeme) + " used").build();
		}

		substitution.stream().map(other -> other.withLineOffset(lineOffset)).forEach(output::add);
	}

	private void assertInAnyIf(TokenStream stream) {
		if (stack.isEmpty()) {
			stream.obtainPreviousToken().error().setDetail("is expected only after conditional directives").raise();
		}
	}

	private void parseDirective(List<Token> output, TokenStream stream, boolean active) {

		if (stream.match("`define")) {
			String name = stream.expect(TokenType.IDENTIFIER).asString();

			if (stream.match("(")) {
				TokenStream args = stream.block("()", "macro arguments");

				// TODO: function-style macros
				if (args.hasNext()) {
					throw UnimplementedException.ofPlural("function-style macros");
				}
			}

			TokenStream body = stream.untilNextLine("directive");

			if (active) macros.put(name, body.toList().stream().filter(token -> token.type != TokenType.BREAK).toList());
			return;
		}

		if (stream.match("`undef")) {
			TokenStream body = stream.untilNextLine("directive");
			String name = body.expect(TokenType.IDENTIFIER).asString();
			body.assertEmpty();

			if (active) macros.remove(name);
			return;
		}

		if (stream.match("`ifdef")) {
			TokenStream body = stream.untilNextLine("directive");
			String name = body.expect(TokenType.IDENTIFIER).asString();
			body.assertEmpty();
			pushBranchDirective(macros.containsKey(name));
			return;
		}

		if (stream.match("`ifndef")) {
			TokenStream body = stream.untilNextLine("directive");
			String name = body.expect(TokenType.IDENTIFIER).asString();
			body.assertEmpty();
			pushBranchDirective(!macros.containsKey(name));
			return;
		}

		if (stream.match("`line")) {
			TokenStream body = stream.untilNextLine("directive");
			Token number = body.expect(TokenType.INTEGER);

			// file name (unit)
			body.expect(TokenType.STRING);

			// level, where
			// - 2: first line after include
			// - 1: last line before include
			// - 0: other
			body.expect(TokenType.INTEGER);

			body.assertEmpty();
			lineOffset = (int) number.asLong() - number.line;
			return;
		}

		if (stream.match("`else")) {
			assertInAnyIf(stream);
			stream.untilNextLine("directive").assertEmpty();
			chainBranchDirective(true);
			return;
		}

		if (stream.match("`elsif")) {
			assertInAnyIf(stream);
			TokenStream body = stream.untilNextLine("directive");
			String name = body.expect(TokenType.IDENTIFIER).asString();
			body.assertEmpty();
			chainBranchDirective(macros.containsKey(name));
			return;
		}

		if (stream.match("`endif")) {
			assertInAnyIf(stream);
			stream.untilNextLine("directive").assertEmpty();
			popBranchDirective();
			return;
		}

		if (stream.match("`include")) {
			TokenStream body = stream.untilNextLine("directive");
			Token path = body.expect(TokenType.STRING);
			body.assertEmpty();

			try {
				output.addAll(tokenizer.tokenizeFile(tokenizer.resolveIncludePath(path.unit.getResource(), path.asString())).preprocess().asTokenStream().toList());
			} catch (IOException e) {
				throw new RuntimeException("Can't include file '" + path + "'", e);
			}
			return;
		}

		// TODO: `if
		if (stream.match("`if")) {
			stream.obtainPreviousToken().error().setUnimplemented().raise();
		}

		substituteMacro(output, stream.next());

	}

	private void preprocess(List<Token> output, TokenStream stream) {

		while (stream.hasNext()) {

			// warning: break should not appear outside of preprocessor directives
			if (stream.match(TokenType.BREAK)) {
				continue;
			}

			stream.startFresh();

			boolean active = stack.isEmpty() || stack.peek().getLogicValue();

			if (stream.peek().type == TokenType.DIRECTIVE) {
				parseDirective(output, stream, active);
				continue;
			}

			// skip tokens until we exit from an 'inactive' block
			if (!active) {
				stream.next();
				continue;
			}

			output.add(stream.next().withLineOffset(lineOffset));
		}

		// generate helpful error message
		if (!stack.isEmpty()) {
			stream.startFresh();
			stream.expect("`endif");
		}
	}

	static class Branch {
		final boolean condition;
		final Branch sibling;

		Branch(boolean condition, Branch sibling) {
			this.condition = condition;
			this.sibling = sibling;
		}

		private boolean anyBefore() {
			if (sibling == null) {
				return false;
			}

			return sibling.condition || sibling.anyBefore();
		}

		public boolean getLogicValue() {
			if (!condition) {
				return false;
			}

			return !anyBefore();
		}
	}
}
