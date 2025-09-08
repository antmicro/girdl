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

import com.antmicro.girdl.data.rdl.BinaryOperator;
import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.List;

public class BinaryExpression extends ExpressionNode {

	private static final List<List<BinaryOperator>> OPERATORS = BinaryOperator.toPrecedenceArrays();

	public final BinaryOperator type;
	public final ExpressionNode left;
	public final ExpressionNode right;

	public BinaryExpression(Location location, BinaryOperator type, ExpressionNode left, ExpressionNode right) {
		super(location);
		this.type = type;
		this.left = left;
		this.right = right;
	}

	public static ExpressionNode parse(TokenStream stream) {
		return binary(stream, 0);
	}

	private static ExpressionNode binary(TokenStream stream, int index) {

		if (index >= OPERATORS.size()) {
			return UnaryExpression.parse(stream);
		}

		int next = index + 1;

		/*
		 * First recurse maximally down and try to create an expression of highers precedence (where index == max)
		 * when that fails return up the stack and try again with a bit lower precedence etc. When we get back here the
		 * expression to our left must have been fully consumed up to our precedence level, meaning all sub-expression of
		 * higher precedence are now consumed and the next operator (if present) is of lower precedence.
		 */
		ExpressionNode expr = binary(stream, next);

		boolean consume = true;

		while (consume && stream.hasNext()) {
			consume = false;

			for (BinaryOperator type : OPERATORS.get(index)) {
				Location location = stream.here();
				if (type.match(stream)) {

					expr = new BinaryExpression(location, type, expr, binary(stream, next));

					// if we consumed some expression try consuming another one
					// this allows chained expressions such as 1 + 2 - 3
					consume = true;
					break;
				}
			}
		}

		return expr;
	}

}
