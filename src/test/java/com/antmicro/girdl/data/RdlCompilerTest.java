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

import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.RenodeRdl;
import com.antmicro.girdl.data.rdl.compiler.Compiler;
import com.antmicro.girdl.data.rdl.compiler.ModelNode;
import com.antmicro.girdl.data.rdl.compiler.Scope;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentType;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentValue;
import com.antmicro.girdl.data.rdl.compiler.model.CompositeType;
import com.antmicro.girdl.data.rdl.compiler.model.ParametricType;
import com.antmicro.girdl.data.rdl.compiler.model.PrimitiveValue;
import com.antmicro.girdl.data.rdl.compiler.model.StructuredValue;
import com.antmicro.girdl.data.rdl.compiler.model.SymbolicType;
import com.antmicro.girdl.data.rdl.compiler.model.TypeValue;
import com.antmicro.girdl.data.rdl.lexer.Tokenizer;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.data.rdl.parser.TokenStream;
import com.antmicro.girdl.data.rdl.parser.ast.RootNode;
import com.antmicro.girdl.test.Util;
import com.antmicro.girdl.util.file.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class RdlCompilerTest {

	@Test
	void testCompilerTopModel() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/empty.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentType top = compiler.getModel();
		ComponentType another = compiler.getModel();

		Assertions.assertEquals(ComponentKind.TOP, top.kind);
		Assertions.assertSame(another, top);

		Assertions.assertEquals(0, top.types().size());
		Assertions.assertEquals(0, top.fields.entries().size());
		Assertions.assertEquals("top", top.name);

	}

	@Test
	void testCompilerEnumAndField() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/basic.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentType top = compiler.getModel();
		Assertions.assertTrue(top.types().containsKey("A"));
		Assertions.assertEquals(1, top.types().size());

		// top will never have values as it is only checked for types
		ComponentValue topValue = (ComponentValue) top.create();
		Assertions.assertEquals(0, topValue.values.size());

		ComponentValue regVal = (ComponentValue) top.getType("A").create();
		Assertions.assertEquals("A", regVal.type.name);
		Assertions.assertEquals(ComponentKind.REGISTER, regVal.type.kind);
		Assertions.assertTrue(regVal.values.containsKey("a"));
		Assertions.assertTrue(regVal.values.containsKey("s"));
		Assertions.assertEquals(0, regVal.getStart());

		// register with unset size
		Assertions.assertEquals(32, regVal.getEnd());

		ComponentValue aVal = (ComponentValue) regVal.values.get("a");
		Assertions.assertEquals(1, aVal.getStart());
		Assertions.assertEquals(9, aVal.getEnd());
		Assertions.assertEquals(8, aVal.getStride());
		Assertions.assertEquals(ComponentValue.STRIDE_PACKED, aVal.stride);
		Assertions.assertEquals(1, aVal.at);
		Assertions.assertEquals(ComponentKind.FIELD, aVal.type.kind);
		Assertions.assertEquals("", aVal.type.name); // anonymous

		StructuredValue sVal = (StructuredValue) regVal.values.get("s");
		Assertions.assertTrue(sVal.values.containsKey("a"));
		Assertions.assertTrue(sVal.values.containsKey("b"));
		Assertions.assertEquals("S", sVal.type.name);

		PrimitiveValue saVal = (PrimitiveValue) sVal.values.get("a");
		Assertions.assertEquals(0, saVal.toLong()); // default int value

	}

	@Test
	void testCompilerExpressions() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/regs_with_expressions.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentValue addrmap = (ComponentValue) compiler.getModel().getType("ABRTCMC").create();
		Assertions.assertEquals("ABRTCMC", addrmap.type.name);

		// the chain breaks here as the next component is not instantiated,
		// just defined so we need to query another type to get to it
		ComponentValue amVal = (ComponentValue) addrmap.type.getType("Inner").create();
		Assertions.assertTrue(amVal.values.containsKey("Reg"));
		Assertions.assertEquals(ComponentKind.ADDRESS_MAP, amVal.type.kind);

		ComponentValue regVal = (ComponentValue) amVal.values.get("Reg");
		Assertions.assertTrue(regVal.values.containsKey("CAP"));
		Assertions.assertTrue(regVal.values.containsKey("regwidth"));
		Assertions.assertEquals(ComponentKind.REGISTER, regVal.type.kind);

		PrimitiveValue regwidthVal = (PrimitiveValue) regVal.values.get("regwidth");
		Assertions.assertEquals(8, regwidthVal.toLong());
		Assertions.assertEquals(8, regVal.getOuterSize());

		ComponentValue fVal = (ComponentValue) regVal.values.get("CAP");
		Assertions.assertEquals(ComponentKind.FIELD, fVal.type.kind);
		Assertions.assertEquals(8, fVal.getOuterSize());
		Assertions.assertTrue(fVal.values.containsKey("sw"));

		SymbolicType.Instance sVal = (SymbolicType.Instance) fVal.values.get("sw");
		Assertions.assertEquals("accesstype", sVal.type.name);

	}

	@Test
	void testCompilerParametricTypes() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/parameters.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentValue addrmap = (ComponentValue) compiler.getModel().getType("myAmap").create();
		Assertions.assertEquals(ComponentKind.ADDRESS_MAP, addrmap.type.kind);

		ComponentValue r16Val = (ComponentValue) addrmap.values.get("reg16");
		Assertions.assertEquals(16, r16Val.getOuterSize());

		ComponentValue r8Val = (ComponentValue) addrmap.values.get("reg8");
		Assertions.assertEquals(8, r8Val.getOuterSize());

	}

	@Test
	void testCompilerNestedInstanceParameters() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/nested_instance_parameters.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentValue addrmap = (ComponentValue) compiler.getModel().getType("Nested").create();
		Assertions.assertEquals(ComponentKind.ADDRESS_MAP, addrmap.type.kind);

		ComponentValue aVal = (ComponentValue) addrmap.values.get("a");
		Assertions.assertEquals(ComponentKind.REGISTER, aVal.type.kind);
		Assertions.assertEquals(32, aVal.getOuterSize());
		Assertions.assertEquals(0, aVal.getStart());

		ComponentValue bVal = (ComponentValue) addrmap.values.get("b");
		Assertions.assertEquals(ComponentKind.REGISTER, bVal.type.kind);
		Assertions.assertEquals(32, bVal.getOuterSize());
		Assertions.assertEquals(32, bVal.getStart());

	}

	@Test
	void testCompiler() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/renode_with_extras.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		CompositeType top = (CompositeType) compiler.getModel().getType("FT5336");
		Assertions.assertTrue(top.types().containsKey("Shared")); // parametric type is still a type
		Assertions.assertTrue(top.types().containsKey("A"));
		Assertions.assertTrue(top.types().containsKey("B"));
		Assertions.assertTrue(top.types().containsKey("myBitFieldEncoding"));
		Assertions.assertTrue(top.types().containsKey("Regs"));

		ComponentValue topVal = (ComponentValue) top.create();
		ComponentValue regsVal = (ComponentValue) topVal.getField("TouchDataRegisters_addrmap").orElseThrow();
		Assertions.assertEquals("Regs", regsVal.type.name);
		Assertions.assertEquals(ComponentKind.ADDRESS_MAP, regsVal.type.kind);

		PrimitiveValue descVal = (PrimitiveValue) regsVal.values.get("desc");
		Assertions.assertEquals(RenodeRdl.ORIGIN, descVal.toString());

		ComponentValue r1Val = (ComponentValue) regsVal.values.get("TouchXHigh");
		Assertions.assertEquals("TouchXHigh", r1Val.values.get("name").toString());
		Assertions.assertEquals(RenodeRdl.GUESSED, r1Val.values.get("desc").toString());
		Assertions.assertEquals(0 * 8, r1Val.at);
		Assertions.assertEquals(8, r1Val.size);
		Assertions.assertTrue(r1Val.values.containsKey("DUMMY"));
		Assertions.assertEquals(ComponentKind.REGISTER, r1Val.type.kind);

		ComponentValue r2Val = (ComponentValue) regsVal.values.get("TouchXLow");
		Assertions.assertEquals("TouchXLow", r2Val.values.get("name").toString());
		Assertions.assertEquals(RenodeRdl.GUESSED, r2Val.values.get("desc").toString());
		Assertions.assertEquals(1 * 8, r2Val.at);
		Assertions.assertEquals(8, r2Val.size);
		Assertions.assertTrue(r2Val.values.containsKey("DUMMY"));
		Assertions.assertEquals(ComponentKind.REGISTER, r2Val.type.kind);

		ComponentValue r3Val = (ComponentValue) regsVal.values.get("TouchYHigh");
		Assertions.assertEquals("TouchYHigh", r3Val.values.get("name").toString());
		Assertions.assertEquals(RenodeRdl.GUESSED, r3Val.values.get("desc").toString());
		Assertions.assertEquals(2 * 8, r3Val.at);
		Assertions.assertEquals(8, r3Val.size);
		Assertions.assertTrue(r3Val.values.containsKey("DUMMY"));
		Assertions.assertEquals(ComponentKind.REGISTER, r3Val.type.kind);

		ComponentValue sVal = (ComponentValue) regsVal.values.get("shared");
		Assertions.assertEquals(ComponentKind.REGISTER, sVal.type.kind);
		Assertions.assertTrue(sVal.values.containsKey("b"));
		Assertions.assertEquals(0xab, sVal.values.get("bfe").toLong()); // defaults to first enum enumeration
		Assertions.assertEquals(true, sVal.values.get("shared").toBool());
	}

	@Test
	void testInvalidRange() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/invalid_range_inst.rdl")).asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ParseError error = Assertions.assertThrows(ParseError.class, () -> {
			compiler.getModel().getType("A").create().dump();
		});

		// we don't try very hard to make the location in the AST be correct,
		// but we should fall vaguely near the problematic part
		Assertions.assertEquals(7, error.line);

	}

	@Test
	void testCompileRegisterSize() throws IOException {

		Tokenizer tokenizer = new Tokenizer();
		tokenizer.setIncludeResolver((ctx, path) -> ctx.map(res -> res.back().find(path)).orElseThrow());

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/reg_sizing.rdl")).preprocess().asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentValue r1 = (ComponentValue) compiler.getModel().getType("R1").create();
		Assertions.assertEquals(32, r1.size);
		Assertions.assertEquals(5, r1.getField("A").orElseThrow().as(ComponentValue.class).at);
		Assertions.assertEquals(12, r1.getField("B").orElseThrow().as(ComponentValue.class).at);
		Assertions.assertEquals(13, r1.getField("C").orElseThrow().as(ComponentValue.class).at);
		Assertions.assertEquals(14, r1.getField("D").orElseThrow().as(ComponentValue.class).at);
		Assertions.assertEquals(15, r1.getField("E").orElseThrow().as(ComponentValue.class).at);

		ComponentValue r2 = (ComponentValue) compiler.getModel().getType("R2").create();
		Assertions.assertEquals(32, r2.size);
		Assertions.assertEquals(8, r2.getField("A").orElseThrow().as(ComponentValue.class).at);
		Assertions.assertEquals(5, r2.getField("B").orElseThrow().as(ComponentValue.class).at);
		Assertions.assertEquals(2, r2.getField("C").orElseThrow().as(ComponentValue.class).at);

	}

	@Test
	void testDefaultRegisterWidth() throws IOException {

		Tokenizer tokenizer = new Tokenizer();
		tokenizer.setIncludeResolver((ctx, path) -> ctx.map(res -> res.back().find(path)).orElseThrow());

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/synthetic/default_reg_size.rdl")).preprocess().asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentValue file = (ComponentValue) compiler.getModel().getType("F").create();

		ComponentValue reg1 = (ComponentValue) file.getField("aa").orElseThrow();
		ComponentValue reg2 = (ComponentValue) file.getField("bb").orElseThrow();
		ComponentValue reg3 = (ComponentValue) file.getField("cc").orElseThrow();

		Assertions.assertEquals(32, reg1.size);
		Assertions.assertEquals(32, reg2.size);
		Assertions.assertEquals(16, reg3.size);

	}

	@Test
	void testCompileI3cCore() throws IOException {

		Util.skipIfNoI3cCore(this);

		Tokenizer tokenizer = new Tokenizer();
		tokenizer.setIncludeResolver((ctx, path) -> ctx.map(res -> res.back().find(path)).orElseThrow());

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/i3c/src/rdl/registers.rdl")).preprocess().asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentType top = compiler.getModel();

		// checks if no exception is thrown
		top.types().values().stream()
				.filter(ParametricType.class::isInstance)
				.map(ParametricType.class::cast)
				.filter(ParametricType::isDefaultable)
				.filter(parametric -> parametric.getTemplateType() == ComponentKind.ADDRESS_MAP)
				.map(parametric -> parametric.implicitize(Scope.empty(), StructuredValue.empty()))
				.map(TypeValue::create);
//				.forEach(ModelNode::dump);

	}

	@Test
	void testCompileI3cCoreWithControllerSupport() throws IOException {

		Util.skipIfNoI3cCore(this);

		Tokenizer tokenizer = new Tokenizer();
		tokenizer.defineMacro("CONTROLLER_SUPPORT");
		tokenizer.setIncludeResolver((ctx, path) -> ctx.map(res -> res.back().find(path)).orElseThrow());

		TokenStream stream = tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/i3c/src/rdl/registers.rdl")).preprocess().asTokenStream();
		RootNode root = RootNode.parse(stream);

		Compiler compiler = new Compiler();
		compiler.compile(root);

		ComponentType top = compiler.getModel();

		// checks if no exception is thrown
		top.types().values().stream()
				.filter(ParametricType.class::isInstance)
				.map(ParametricType.class::cast)
				.filter(ParametricType::isDefaultable)
				.filter(parametric -> parametric.getTemplateType() == ComponentKind.ADDRESS_MAP)
				.map(parametric -> parametric.implicitize(Scope.empty(), StructuredValue.empty()))
				.map(TypeValue::create);
//				.forEach(ModelNode::dump);

	}

}
