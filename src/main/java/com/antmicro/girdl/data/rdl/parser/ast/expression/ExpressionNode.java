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
package com.antmicro.girdl.data.rdl.parser.ast.expression;

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.SyntaxNode;

import java.util.Optional;

public abstract class ExpressionNode extends SyntaxNode {

	protected ExpressionNode(Location location) {
		super(location);
	}

	public static ExpressionNode parseExpression(TokenStream stream) {
		return TernaryOperatorNode.parse(stream);
	}

	public static ExpressionNode parsePrimary(TokenStream stream) {

		if (stream.match("(")) {
			return parseExpression(stream.block("()", "expression"));
		}

		return parseLiteral(stream);
	}

	public static ExpressionNode parseLiteral(TokenStream stream) {

		Location location = stream.here();
		if (stream.match("true")) return new BoolNode(location, true);
		if (stream.match("false")) return new BoolNode(location, false);

		Optional<Token> string = stream.accept(TokenType.STRING);
		if (string.isPresent()) {
			return new StringNode(location, string.get().asString());
		}

		Optional<Token> integer = stream.accept(TokenType.INTEGER);
		if (integer.isPresent()) {
			return new IntegerNode(location, integer.get().asLong());
		}

		String id = stream.expect(TokenType.IDENTIFIER).asString();

		if (stream.match("::")) {
			String enumeration = stream.expect(TokenType.IDENTIFIER).asString();

			return new EnumLiteralNode(location, id, enumeration);
		}

		if (stream.match("'")) {
			stream.match("{");

			// we need a lookahead here as we can't tell until we read
			// the key-value separator whether this is array or struct literal
			if (stream.lookahead(boxed -> boxed.match(TokenType.IDENTIFIER) && boxed.match(":"))) {
				return StructLiteralNode.parseStructLiteral(stream.block("{}", "struct literal"));
			}

			return ArrayLiteralNode.parse(stream.block("{}", "array literal"));
		}

		return LiteralNode.parse(location, id, stream);
	}

}
