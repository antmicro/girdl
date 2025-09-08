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

import com.antmicro.girdl.data.rdl.Token;

public class Postprocessor {

	public static Object none(Token token) {
		return null;
	}

	public static Object directive(Token token) {
		return token.lexeme.substring(1);
	}

	public static Object identifier(Token token) {
		String lexeme = token.lexeme;

		if (lexeme.startsWith("\\")) {
			return lexeme.substring(1);
		}

		return lexeme;
	}

	public static Object string(Token token) {
		String lexeme = token.lexeme;
		StringBuilder builder = new StringBuilder();

		boolean escape = false;

		for (int i = 1; i < lexeme.length() - 1; i ++) {
			char c = lexeme.charAt(i);

			if (escape) {
				if (c == '\\') builder.append('\\');
				if (c == '"') builder.append('"');

				escape = false;
				continue;
			}

			if (c == '\\') {
				escape = true;
				continue;
			}

			builder.append(c);
		}

		return builder.toString();
	}

	public static Object integer(Token token) {
		if (token.lexeme.contains("'")) {
			return verilogInteger(token);
		}

		return simpleInteger(token);
	}

	private static Object verilogInteger(Token token) {

		// get only the part after the width specifier
		String numeric = token.lexeme.split("'")[1].replaceAll("_", "");

		try {
			char first = numeric.charAt(0);

			if (first == 'h' || first == 'H') {
				return Long.valueOf(numeric.substring(1), 16);
			}

			if (first == 'd' || first == 'D') {
				return Long.valueOf(numeric.substring(1), 10);
			}

			if (first == 'b' || first == 'B') {
				return Long.valueOf(numeric.substring(1), 2);
			}

		} catch (NumberFormatException e) {
			token.error().setDetail("is not a valid verilog-style number").raise();
		}

		// prefix is validated by tokenizer
		throw new RuntimeException("Unreachable statement!");
	}

	private static Object simpleInteger(Token token) {
		return Long.decode(token.lexeme.replaceAll("_", ""));
	}

}
