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
package com.antmicro.girdl.data;

import com.antmicro.girdl.data.rdl.BinaryOperator;
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.UnaryOperator;
import com.antmicro.girdl.data.rdl.lexer.Tokenizer;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.ComponentDefinitionNode;
import com.antmicro.girdl.data.rdl.parser.ast.ComponentInstanceNode;
import com.antmicro.girdl.data.rdl.parser.ast.EnumNode;
import com.antmicro.girdl.data.rdl.parser.ast.ExplicitInstantiationNode;
import com.antmicro.girdl.data.rdl.parser.ast.InstantiationType;
import com.antmicro.girdl.data.rdl.parser.ast.PropertyAssignmentNode;
import com.antmicro.girdl.data.rdl.parser.ast.RootNode;
import com.antmicro.girdl.data.rdl.parser.ast.StructNode;
import com.antmicro.girdl.data.rdl.parser.ast.TypedEntryNode;
import com.antmicro.girdl.data.rdl.parser.ast.ValuedEntryNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.ArrayLiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.BinaryExpression;
import com.antmicro.girdl.data.rdl.parser.ast.expression.BoolNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.ExpressionNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.IntegerNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.LiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.StringNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.StructLiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.TernaryOperatorNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.UnaryExpression;
import com.antmicro.girdl.util.file.Resource;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;
import java.util.function.Consumer;

public class RdlParserTest {

	@Test
	public void testParser() {

		Tokenizer tokenizer = new Tokenizer();
		TokenStream stream = tokenizer.tokenizeString("alpha beta 42 123 0xFF [ a b [c d] x ] e f g").asTokenStream();

		stream.expect("alpha");

		Assertions.assertThrows(ParseError.class, () -> stream.expect(TokenType.INTEGER));
		Assertions.assertThrows(ParseError.class, () -> stream.expect("alpha"));
		Assertions.assertEquals("beta", stream.accept(TokenType.IDENTIFIER).orElseThrow().asString());

		Assertions.assertEquals(42, stream.accept(TokenType.INTEGER).orElseThrow().asLong());
		Assertions.assertEquals(123, stream.accept(TokenType.INTEGER).orElseThrow().asLong());
		Assertions.assertEquals(0xFF, stream.accept(TokenType.INTEGER).orElseThrow().asLong());

		stream.accept("[");
		TokenStream inner = stream.block("[]", "inner");

		stream.expect("e");
		stream.expect("f");
		stream.expect("g");
		Assertions.assertTrue(stream.isEmpty());

		inner.expect("a");
		inner.expect("b");
		inner.expect("[");
		inner.expect("c");
		inner.expect("d");
		inner.expect("]");
		inner.expect("x");

		Assertions.assertTrue(inner.isEmpty());
		Assertions.assertTrue(inner.toList().isEmpty());

	}

	@Test
	public void testParserUntil() {

		Tokenizer tokenizer = new Tokenizer();
		TokenStream stream = tokenizer.tokenizeString("a b c ; d e f").asTokenStream();

		TokenStream inner = stream.until(";", "abc").trim();
		inner.expect("a");
		inner.expect("b");
		inner.expect("c");

		Assertions.assertTrue(inner.isEmpty());

		stream.expect("d");
		stream.expect("e");
		stream.expect("f");

	}

	@Test
	public void testParserUntilNextLine() {

		Tokenizer tokenizer = new Tokenizer();
		TokenStream stream = tokenizer.tokenizeString("0 a b c \n d e f").asTokenStream();

		stream.expect("0");

		TokenStream inner = stream.untilNextLine("abc");
		inner.expect("a");
		inner.expect("b");
		inner.expect("c");

		Assertions.assertTrue(inner.isEmpty());

		stream.expect("d");
		stream.expect("e");
		stream.expect("f");

	}

	@Test
	public void testParserRenodeRdlNoException() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/ABRTCMC.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals("ABRTCMC", root.children.getFirst().as(ComponentDefinitionNode.class).name);

	}

	@Test
	public void testParserRdlBasicExpressionPrecedence() {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeString("1 + 2 * 3 - !(a / b)").asTokenStream();
		BinaryExpression expr = ExpressionNode.parseExpression(stream).as(BinaryExpression.class);

		// test basic precedence rules
		Assertions.assertEquals(BinaryOperator.MINUS, expr.type);
		Assertions.assertEquals(BinaryOperator.PLUS, expr.left.as(BinaryExpression.class).type);
		Assertions.assertEquals(BinaryOperator.MULTIPLY, expr.left.as(BinaryExpression.class).right.as(BinaryExpression.class).type);
		Assertions.assertEquals(UnaryOperator.LOGICAL_NOT, expr.right.as(UnaryExpression.class).type);
		Assertions.assertEquals(BinaryOperator.DIVIDE, expr.right.as(UnaryExpression.class).node.as(BinaryExpression.class).type);

	}

	@Test
	public void testParserRdlRegisterWithExpression() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/regs_with_expressions.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);


		Assertions.assertEquals(BinaryOperator.POWER, root.children.getFirst()
				.as(ComponentDefinitionNode.class).children.getFirst()
				.as(ComponentDefinitionNode.class).children.getFirst()
				.as(ComponentInstanceNode.class).component
				.as(ComponentDefinitionNode.class).children.getFirst()
				.as(PropertyAssignmentNode.class).value
				.as(BinaryExpression.class).right
				.as(BinaryExpression.class).left
				.as(BinaryExpression.class).left
				.as(BinaryExpression.class).type);

	}

	@Test
	public void testParserEnum() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/enum.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals(2, root.children.size());
		Assertions.assertEquals("myBitFieldEncoding", root.children.get(0).as(EnumNode.class).name);
		Assertions.assertEquals("a", root.children.get(1).as(ComponentInstanceNode.class).name);

		EnumNode en = root.children.getFirst().as(EnumNode.class);

		Assertions.assertEquals(4, en.entries.size());
		Assertions.assertEquals("first_encoding_entry", en.entries.get(0).name);
		Assertions.assertEquals(171, en.entries.get(0).value.as(IntegerNode.class).value);
		Assertions.assertEquals("second_entry", en.entries.get(1).name);
		Assertions.assertEquals(205, en.entries.get(1).value.as(IntegerNode.class).value);
		Assertions.assertEquals("third_entry", en.entries.get(2).name);
		Assertions.assertEquals(239, en.entries.get(2).value.as(IntegerNode.class).value);
		Assertions.assertEquals("fourth_entry", en.entries.get(3).name);
		Assertions.assertEquals(147, en.entries.get(3).value.as(IntegerNode.class).value);

		Assertions.assertEquals(2, en.entries.get(2).properties.size());
		Assertions.assertEquals("third entry, just like others", en.entries.get(2).properties.getFirst().value.as(StringNode.class).value);

	}

	@Test
	public void testParserStruct() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/struct_simple.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals(2, root.children.size());
		Assertions.assertEquals("struct_1", root.children.get(0).as(StructNode.class).name);
		Assertions.assertEquals("struct_2", root.children.get(1).as(StructNode.class).name);

		StructNode sn = root.children.getFirst().as(StructNode.class);

		Assertions.assertEquals(1, sn.entries.size());
		Assertions.assertEquals("foo", sn.entries.getFirst().name);
		Assertions.assertFalse(sn.entries.getFirst().isArray);

	}

	@Test
	public void testParserStructLiteral() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/struct_literal.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals("a", root.children.getLast().as(ComponentDefinitionNode.class).children.getFirst().as(PropertyAssignmentNode.class).value.as(StructLiteralNode.class).entries.get(0).name);
		Assertions.assertEquals("b", root.children.getLast().as(ComponentDefinitionNode.class).children.getFirst().as(PropertyAssignmentNode.class).value.as(StructLiteralNode.class).entries.get(1).name);
	}

	@Test
	public void testParserArrayLiteral() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/array_literal.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals("hello", root.children.getFirst().as(ComponentDefinitionNode.class).children.get(0).as(PropertyAssignmentNode.class).value.as(ArrayLiteralNode.class).entries.get(0).as(StringNode.class).value);
		Assertions.assertEquals("world", root.children.getFirst().as(ComponentDefinitionNode.class).children.get(0).as(PropertyAssignmentNode.class).value.as(ArrayLiteralNode.class).entries.get(1).as(StringNode.class).value);

	}

	@Test
	public void testParserExplicitInstantiation() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/instantiation.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals(4, root.children.size());
		Assertions.assertEquals("MyReg", root.children.get(1).as(ExplicitInstantiationNode.class).instance.component.name);
		Assertions.assertEquals("a", root.children.get(1).as(ExplicitInstantiationNode.class).instance.name);

	}

	@Test
	public void testParseInlineInstantiationType() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/RenesasRZG_IRQController.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals(InstantiationType.EXTERNAL, root.children.getFirst()
				.as(ComponentDefinitionNode.class).children.getFirst()
				.as(ComponentInstanceNode.class).component
				.as(ComponentDefinitionNode.class).children.get(5)
				.as(ComponentInstanceNode.class).type);
	}

	@Test
	public void testParsePreprocessorDirectives() throws IOException {

		List<Pair<Consumer<Tokenizer>, Integer>> configs = List.of(
				Pair.of(tokenizer -> {}, 3),
				Pair.of(tokenizer -> tokenizer.defineMacro("VARIANT0"), 8),
				Pair.of(tokenizer -> tokenizer.defineMacro("VARIANT5"), 11)
		);

		for (Pair<Consumer<Tokenizer>, Integer> config : configs) {
			Tokenizer tokenizer = new Tokenizer();
			config.getLeft().accept(tokenizer);

			TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/AmbiqApollo4_GPIO.rdl")).preprocess().asTokenStream();
			RootNode root = RootNode.parse(stream);

			Assertions.assertEquals(config.getRight(), root.children.getFirst()
					.as(ComponentDefinitionNode.class).children.getFirst()
					.as(ComponentInstanceNode.class).component
					.as(ComponentDefinitionNode.class).children.get(1)
					.as(ComponentInstanceNode.class).component
					.as(ComponentDefinitionNode.class).children.size());
		}

	}

	@Test
	public void testPreprocessorIfElse() throws IOException {

		Tokenizer tokenizer = new Tokenizer();
		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/preprocessor.rdl")).preprocess().asTokenStream();

		Assertions.assertEquals(stream.toList().stream().map(token -> token.lexeme).toList(), List.of("token_first_1", "token_first_3", "token_second_3", "token_b"));

	}

	@Test
	public void testPreprocessorMultiline() throws IOException {

		Tokenizer tokenizer = new Tokenizer();
		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/preprocessor_multiline.rdl")).preprocess().asTokenStream();

		Assertions.assertEquals("name", RootNode.parse(stream).children.getFirst()
				.as(ComponentDefinitionNode.class).children.getFirst()
				.as(ComponentDefinitionNode.class).children.getFirst()
				.as(PropertyAssignmentNode.class).reference.instances.getFirst().name);

	}

	@Test
	public void testPreprocessorLine() throws IOException {

		Tokenizer tokenizer = new Tokenizer();
		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/preprocessor_line.rdl")).preprocess().asTokenStream();

		ComponentDefinitionNode reg = RootNode.parse(stream).children.getFirst().as(ComponentDefinitionNode.class);

		Assertions.assertEquals(3, reg.children.get(0).as(PropertyAssignmentNode.class).value.as(IntegerNode.class).value);
		Assertions.assertEquals(4001, reg.children.get(1).as(PropertyAssignmentNode.class).value.as(IntegerNode.class).value);

	}

	@Test
	public void testPreprocessorInvalidChain() {
		Tokenizer tokenizer = new Tokenizer();

		Assertions.assertThrows(ParseError.class, () -> {
			tokenizer.tokenizeString("`else").preprocess();
		});

		Assertions.assertThrows(ParseError.class, () -> {
			tokenizer.tokenizeString("`elsif").preprocess();
		});

		// make sure we get `endif after `ifdef
		Assertions.assertThrows(ParseError.class, () -> {
			tokenizer.tokenizeString("`ifdef TEST").preprocess();
		});
	}

	@Test
	public void testPreprocessorInclude() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		tokenizer.setIncludeResolver((ctx, path) -> ctx.map(res -> res.back().find(path)).orElseThrow());

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/include.rdl")).preprocess().asTokenStream();
		stream.expect("token_first_1");
	}

	@Test
	public void testParserComponentParameters() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/parameters.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals("SIZE", root.children.get(0).as(ComponentDefinitionNode.class).parameters.get(0).as(TypedEntryNode.class).name);
		Assertions.assertEquals(true, root.children.get(0).as(ComponentDefinitionNode.class).parameters.get(1).as(ValuedEntryNode.class).value.as(BoolNode.class).value);

	}

	@Test
	public void testTernaryOperator() {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeString("a < 0 ? 0 : a").asTokenStream();
		TernaryOperatorNode ternary = ExpressionNode.parseExpression(stream).as(TernaryOperatorNode.class);

		Assertions.assertEquals(BinaryOperator.LESS_THAN, ternary.condition.as(BinaryExpression.class).type);
		Assertions.assertEquals(0, ternary.then.as(IntegerNode.class).value);
		Assertions.assertEquals("a", ternary.otherwise.as(LiteralNode.class).literals.getFirst());
	}

	@Test
	public void testSignal() throws IOException {
		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/signal.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertEquals(ComponentKind.SIGNAL, root.children.getFirst(/*addrmap*/).as(ComponentDefinitionNode.class).children.getFirst(/*signal*/).as(ComponentInstanceNode.class).component.as(ComponentDefinitionNode.class).type);
	}

	@Test
	void testDefaultAssignment() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/defaulted.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Assertions.assertTrue(root.children.getFirst(/*regfile*/).as(ComponentDefinitionNode.class).children.get(0/*default regwidth=32*/).as(PropertyAssignmentNode.class).isDefault);
		Assertions.assertFalse(root.children.getFirst(/*regfile*/).as(ComponentDefinitionNode.class).children.get(1/*name="hi"*/).as(PropertyAssignmentNode.class).isDefault);

	}

	@Test
	void testNonLeafField() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/non_leaf_field.rdl")).asTokenStream();
		ParseError error = Assertions.assertThrows(ParseError.class, () -> RootNode.parse(stream));

		Assertions.assertEquals(3, error.line);


	}

}
