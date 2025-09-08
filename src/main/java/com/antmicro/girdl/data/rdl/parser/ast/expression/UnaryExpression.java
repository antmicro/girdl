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
import com.antmicro.girdl.data.rdl.UnaryOperator;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

public class UnaryExpression extends ExpressionNode {

	public final UnaryOperator type;
	public final ExpressionNode node;

	public UnaryExpression(Location location, UnaryOperator type, ExpressionNode node) {
		super(location);
		this.type = type;
		this.node = node;
	}

	public static ExpressionNode parse(TokenStream stream) {

		for (UnaryOperator type : UnaryOperator.values()) {
			Location location = stream.here();

			if (type.match(stream)) {
				return new UnaryExpression(location, type, ExpressionNode.parsePrimary(stream));
			}
		}

		return ExpressionNode.parsePrimary(stream);

	}

}
