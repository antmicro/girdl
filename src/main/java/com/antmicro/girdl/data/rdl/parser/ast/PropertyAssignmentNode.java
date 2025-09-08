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
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.PropertyModifier;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.expression.BoolNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.ExpressionNode;

import java.util.Optional;

public class PropertyAssignmentNode extends SyntaxNode {

	public final PropertyReferenceNode reference;
	public final ExpressionNode value;
	public final boolean isDefault;

	public PropertyAssignmentNode(Location location, PropertyReferenceNode reference, ExpressionNode value, boolean isDefault) {
		super(location);
		this.reference = reference;
		this.value = value;
		this.isDefault = isDefault;
	}

	private static Optional<PropertyModifier> tryParseModifier(TokenStream stream) {
		try {
			return stream.accept(TokenType.RESERVED).map(token -> token.lexeme).map(PropertyModifier::valueOf);
		} catch (Exception e) {
			return Optional.empty();
		}
	}

	/**
	 * Explicit assignments are a simplified subset of normal property assignments.
	 */
	public static PropertyAssignmentNode parseExplicit(TokenStream stream) {

		Token identifier = stream.expect(TokenType.IDENTIFIER);
		String name = identifier.asString();
		stream.expect("=");

		ExpressionNode node = ExpressionNode.parseExpression(stream);
		return new PropertyAssignmentNode(identifier, new PropertyReferenceNode(identifier, name), node, false);
	}

	public static SyntaxNode parse(TokenStream stream) {

		boolean isDefault = false;
		Location location = stream.here();

		if (stream.match("default")) {
			isDefault = true;
		}

		Optional<PropertyModifier> modifier = tryParseModifier(stream);
		PropertyReferenceNode reference = PropertyReferenceNode.parse(stream);

		if (modifier.isPresent()) {
			return new PropertyModifierNode(location, reference, modifier.get());
		}

		// as per the SystemRDL specification 2.0 (5.1.3.1) if the expression is omitted the
		// property is assumed to be of type Boolean and assigned a true value
		ExpressionNode node = new BoolNode(location, true);

		if (stream.match("=")) {
			node = ExpressionNode.parseExpression(stream);
		}

		stream.assertEmpty();

		return new PropertyAssignmentNode(location, reference, node, isDefault);
	}

}

