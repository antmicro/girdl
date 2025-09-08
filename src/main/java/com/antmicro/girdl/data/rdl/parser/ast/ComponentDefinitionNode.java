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
import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.expression.StructLiteralNode;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class ComponentDefinitionNode extends ComponentNode {

	public final ComponentKind type;
	public final List<SyntaxNode> children;
	public final List<SyntaxNode> parameters;

	public ComponentDefinitionNode(Location location, String name, ComponentKind type, List<SyntaxNode> children, List<SyntaxNode> parameters) {
		super(location, name);
		this.type = type;
		this.children = children;
		this.parameters = parameters;
	}

	static List<SyntaxNode> parseBody(TokenStream stream, Function<TokenStream, SyntaxNode> parser) {
		List<SyntaxNode> nodes = new ArrayList<>();

		while (stream.hasNext()) {
			nodes.add(parser.apply(stream));
		}

		return nodes;
	}

	private static StructLiteralNode parseParameterLiteral(TokenStream stream) {

		if (stream.match("#")) {
			stream.expect("(");

			TokenStream literal = stream.block("()", "parameters block");
			return StructLiteralNode.parseParameterLiteral(literal);
		}

		return new StructLiteralNode(stream.obtainPreviousToken(), List.of());
	}

	private static SyntaxNode parse(TokenStream stream, ComponentKind type, InstantiationType inst) {

		// components can be either definitive or anonymous
		String name = stream.accept(TokenType.IDENTIFIER).map(Token::asString).orElse("");

		List<SyntaxNode> parameterDefinition = List.of();

		if (stream.match("#")) {
			stream.expect("(");

			TokenStream definition = stream.block("()", "parameters block");
			parameterDefinition = ParseUtil.parseList(definition, ValuedEntryNode::parse, ",");
		}

		Location location = stream.expect("{");
		List<SyntaxNode> children = parseBody(stream.block("{}", "component"), type.isLeaf()
				? ComponentDefinitionNode::parseLeaf
				: ComponentDefinitionNode::parseNode);

		ComponentDefinitionNode node = new ComponentDefinitionNode(location, name, type, children, parameterDefinition);

		// simple component definition w/o instantiation
		if (stream.match(";")) {
			return node;
		}

		// the type can be either at the start or right before instance name
		if (inst == InstantiationType.UNDEFINED) {
			inst = InstantiationType.parse(stream);
		}

		StructLiteralNode parameterLiteral = parseParameterLiteral(stream);

		// TODO: rework this, we need to support comma separated lists here
		return ComponentInstanceNode.parse(node, stream.until(";", "instantiation"), inst, parameterLiteral);

	}

	public static SyntaxNode parseNode(TokenStream stream) {

		// optionally consumes internal/external keyword from the stream
		InstantiationType type = InstantiationType.parse(stream);

		// component definition
		if (stream.match("addrmap")) return parse(stream, ComponentKind.ADDRESS_MAP, type);
		if (stream.match("regfile")) return parse(stream, ComponentKind.REGISTER_FILE, type);
		if (stream.match("reg")) return parse(stream, ComponentKind.REGISTER, type);
		if (stream.match("field")) return parse(stream, ComponentKind.FIELD, type);
		if (stream.match("mem")) return parse(stream, ComponentKind.MEMORY, type);
		if (stream.match("signal")) return parse(stream, ComponentKind.SIGNAL, type);

		return parse(stream, type);

	}

	private static SyntaxNode parseLeaf(TokenStream stream) {

		// optionally consumes internal/external keyword from the stream
		InstantiationType type = InstantiationType.parse(stream);

		return parse(stream, type);

	}

	private static SyntaxNode parse(TokenStream stream, InstantiationType type) {

		if (stream.match("enum")) return EnumNode.parse(stream);
		if (stream.match("constraint")) return ConstraintNode.parse(stream);

		/*
		 * Try parsing a struct, here we have two entry
		 * points as a struct can be prepended with an 'abstract' keyword
		 */

		if (stream.match("abstract")) {
			stream.expect("struct");

			return StructNode.parse(stream, true);
		}

		if (stream.match("struct")) {
			return StructNode.parse(stream, false);
		}

		/*
		 * Try parsing explicit component instantiation,
		 * this is a bit messy bc it's hard to detect this in a RDP
		 */

		boolean instantiation = false;
		String alias = "";

		// if we have type here we assume this is an explicit instantiation
		// as that keyword can't be used prior to property assignments
		if (type != InstantiationType.UNDEFINED) {
			instantiation = true;
		}

		if (stream.match("alias")) {
			alias = stream.expect(TokenType.IDENTIFIER).asString();
			instantiation = true;
		}

		// if we are still not sure, we need to look for a "double identifier" or for a parameter instantiation block
		// those are never (?) valid in property assignments
		if (!instantiation && stream.lookahead(boxed -> boxed.match(TokenType.IDENTIFIER) && (boxed.match(TokenType.IDENTIFIER) || boxed.match("#")))) {
			instantiation = true;
		}

		// now we should know 100%
		if (instantiation) {
			Token identifier = stream.expect(TokenType.IDENTIFIER);
			String typeToUse = identifier.asString();

			StructLiteralNode parameterLiteral = parseParameterLiteral(stream);

			ComponentNode component = new ComponentNode(identifier, typeToUse);
			ComponentInstanceNode instance = ComponentInstanceNode.parse(component, stream, type, parameterLiteral);

			stream.expect(";");
			return new ExplicitInstantiationNode(identifier, alias, instance);
		}

		/*
		 * If we still did not match then this must be a property assignment
		 * or there was some mistake when detecting the explicit instantiation (both are grammatically complex)
		 */

		return PropertyAssignmentNode.parse(stream.until(";", "property").trim());
	}

}
