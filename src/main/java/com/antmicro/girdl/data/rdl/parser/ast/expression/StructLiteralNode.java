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
import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.SyntaxNode;

import java.util.List;

public class StructLiteralNode extends ExpressionNode {

	public final List<EntryNode> entries;

	public StructLiteralNode(Location location, List<EntryNode> entries) {
		super(location);
		this.entries = entries;
	}

	public static StructLiteralNode parseStructLiteral(TokenStream stream) {
		return new StructLiteralNode(stream.here(), ParseUtil.parseList(stream, EntryNode::parseStructEntry, ","));
	}

	public static StructLiteralNode parseParameterLiteral(TokenStream stream) {
		return new StructLiteralNode(stream.here(), ParseUtil.parseList(stream, EntryNode::parseParameterEntry, ","));
	}

	public static class EntryNode extends SyntaxNode {

		public final String name;
		public final ExpressionNode value;

		public EntryNode(Location location, String name, ExpressionNode value) {
			super(location);
			this.name = name;
			this.value = value;
		}

		public static EntryNode parseStructEntry(TokenStream stream) {
			Token identifier = stream.expect(TokenType.IDENTIFIER);
			String name = identifier.asString();
			stream.expect(":");

			ExpressionNode expression = ExpressionNode.parseExpression(stream);

			return new EntryNode(identifier, name, expression);
		}

		public static EntryNode parseParameterEntry(TokenStream stream) {
			Location location = stream.expect(".");
			String name = stream.expect(TokenType.IDENTIFIER).asString();
			stream.expect("(");
			TokenStream inner = stream.block("()", "expression");

			ExpressionNode expression = ExpressionNode.parseExpression(inner);
			inner.assertEmpty();

			return new EntryNode(location, name, expression);
		}

	}


}
