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
package com.antmicro.girdl.data.rdl.parser.ast;

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.expression.ExpressionNode;

public class ValuedEntryNode extends SyntaxNode {

	public final TypedEntryNode type;
	public final ExpressionNode value;

	public ValuedEntryNode(Location location, TypedEntryNode type, ExpressionNode value) {
		super(location);
		this.type = type;
		this.value = value;
	}

	public static SyntaxNode parse(TokenStream stream) {
		Location location = stream.here();
		TypedEntryNode type = TypedEntryNode.parse(stream);

		if (!stream.match("=")) {
			return type;
		}

		// potentially make ValuedEntryNode extend TypedEntryNode
		ExpressionNode value = ExpressionNode.parseExpression(stream);
		return new ValuedEntryNode(location, type, value);
	}

}
