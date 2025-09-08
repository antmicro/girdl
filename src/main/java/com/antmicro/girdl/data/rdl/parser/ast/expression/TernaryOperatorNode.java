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
import com.antmicro.girdl.data.rdl.parser.TokenStream;

public class TernaryOperatorNode extends ExpressionNode {

	public final ExpressionNode condition;
	public final ExpressionNode then;
	public final ExpressionNode otherwise;

	public TernaryOperatorNode(Location location, ExpressionNode condition, ExpressionNode then, ExpressionNode otherwise) {
		super(location);
		this.condition = condition;
		this.then = then;
		this.otherwise = otherwise;
	}

	public static ExpressionNode parse(TokenStream stream) {

		ExpressionNode condition = BinaryExpression.parse(stream);

		if (stream.isEmpty()) {
			return condition;
		}

		Location location = stream.here();

		if (!stream.match("?")) {
			return condition;
		}

		ExpressionNode then = BinaryExpression.parse(stream);
		stream.expect(":");
		ExpressionNode otherwise = BinaryExpression.parse(stream);

		return new TernaryOperatorNode(location, condition, then, otherwise);
	}

}
