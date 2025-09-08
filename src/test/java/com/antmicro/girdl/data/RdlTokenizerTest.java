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
import com.antmicro.girdl.data.rdl.SourceUnit;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.lexer.SymbolPredicate;
import com.antmicro.girdl.data.rdl.lexer.SymbolStream;
import com.antmicro.girdl.data.rdl.lexer.Tokenizer;
import com.antmicro.girdl.util.file.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

public class RdlTokenizerTest {

	@Test
	public void testSymbolStream() {

		String source = "ab\rba\ncab";
		SymbolStream stream = new SymbolStream(source, SourceUnit.ofString("<string>"));

		Assertions.assertEquals(1, stream.getLine());
		Assertions.assertEquals(1, stream.getColumn());

		Assertions.assertTrue(stream.accept('a'));
		Assertions.assertFalse(stream.accept('c'));
		stream.expect('b');
		stream.expect('b');

		Assertions.assertEquals(1, stream.getLine());
		Assertions.assertEquals(5, stream.getColumn());

		ParseError error = Assertions.assertThrows(ParseError.class, () -> stream.expect('f'));
		Assertions.assertEquals(1, error.line);
		Assertions.assertEquals(5, error.column);

		stream.expect('a');
		Assertions.assertEquals(2, stream.getLine());
		Assertions.assertEquals(0, stream.getColumn()); // new line is at column 0

		Assertions.assertFalse(stream.isEmpty());
		stream.expect('\n');

		Assertions.assertEquals(2, stream.getLine());
		Assertions.assertEquals(1, stream.getColumn());

		stream.expect('c');
		stream.expect('a');

		Assertions.assertFalse(stream.isEmpty());
		stream.expect('b');
		Assertions.assertTrue(stream.isEmpty());

		final SymbolPredicate any = new SymbolPredicate(c -> true, "any");

		Assertions.assertThrows(ParseError.class, () -> stream.expect(any));
		Assertions.assertThrows(ParseError.class, () -> stream.accept(any));
		Assertions.assertThrows(ParseError.class, () -> stream.next());
		Assertions.assertThrows(ParseError.class, () -> stream.peek());

	}

	@Test
	public void testTokenizer() {

		Tokenizer tokenizer = new Tokenizer();
		Token[] tokens = tokenizer.tokenizeString("\\some_name \"string with spaces\" \n\nname12345 \"Escape \\\\ \\\"\" \"dense\"END_OF_LINE").tokens.toArray(Token[]::new);

		Assertions.assertEquals("\\some_name", tokens[0].lexeme);
		Assertions.assertEquals(TokenType.IDENTIFIER, tokens[0].type);
		Assertions.assertEquals(1, tokens[0].line);
		Assertions.assertEquals(1, tokens[0].column);

		Assertions.assertEquals("\"string with spaces\"", tokens[1].lexeme);
		Assertions.assertEquals(TokenType.STRING, tokens[1].type);
		Assertions.assertEquals(1, tokens[1].line);

		Assertions.assertEquals("name12345", tokens[2].lexeme);
		Assertions.assertEquals(TokenType.IDENTIFIER, tokens[2].type);
		Assertions.assertEquals(3, tokens[2].line);
		Assertions.assertEquals(1, tokens[2].column);

		Assertions.assertEquals("\"Escape \\\\ \\\"\"", tokens[3].lexeme);
		Assertions.assertEquals(TokenType.STRING, tokens[3].type);
		Assertions.assertEquals(3, tokens[3].line);

		Assertions.assertEquals("\"dense\"", tokens[4].lexeme);
		Assertions.assertEquals(TokenType.STRING, tokens[4].type);
		Assertions.assertEquals(3, tokens[4].line);

		Assertions.assertEquals("END_OF_LINE", tokens[5].lexeme);
		Assertions.assertEquals(TokenType.IDENTIFIER, tokens[5].type);
		Assertions.assertEquals(3, tokens[5].line);

	}

	@Test
	public void testTokenizerLineTracking() {

		Tokenizer tokenizer = new Tokenizer();
		Token[] tokens = tokenizer.tokenizeString("\na\n\nb").tokens.toArray(Token[]::new);

		Assertions.assertEquals(2, tokens[0].line);
		Assertions.assertEquals(4, tokens[1].line);

	}

	@Test
	public void testVerilogStyleNumber() {

		Tokenizer tokenizer = new Tokenizer();
		Token[] tokens = tokenizer.tokenizeString("32'D123 16'HFF 8'b1010").tokens.toArray(Token[]::new);

		Assertions.assertEquals(123, tokens[0].asLong());
		Assertions.assertEquals(0xFF, tokens[1].asLong());
		Assertions.assertEquals(0b1010, tokens[2].asLong());

	}

	@Test
	public void testValidSpacedNumber() {

		Tokenizer tokenizer = new Tokenizer();
		Token[] tokens = tokenizer.tokenizeString("100_000 0x1_f_f 16'h1_f_f").tokens.toArray(Token[]::new);

		Assertions.assertEquals(100000, tokens[0].asLong());
		Assertions.assertEquals(0x1ff, tokens[1].asLong());
		Assertions.assertEquals(0x1ff, tokens[2].asLong());

	}

	@Test
	public void testInvalidSpacedNumber() {

		Tokenizer tokenizer = new Tokenizer();

		Assertions.assertThrows(ParseError.class, () -> tokenizer.tokenizeString("0x_1"));
		Assertions.assertThrows(ParseError.class, () -> tokenizer.tokenizeString("16'h_1"));

		// according to the SystemRDL specification 2.0 this one SHOULD also fail
		// but in order to simplify the parser we will treat it as valid
		Assertions.assertDoesNotThrow(() -> tokenizer.tokenizeString("1_6'h1"));

	}

	@Test
	public void testValidStrings() {

		Tokenizer tokenizer = new Tokenizer();
		Token[] tokens = tokenizer.tokenizeString("\"string \n continued\"" ).tokens.toArray(Token[]::new);
		Assertions.assertEquals("string \n continued", tokens[0].asString());
	}

	@Test
	public void testInvalidStrings() {

		Tokenizer tokenizer = new Tokenizer();
		Assertions.assertThrows(ParseError.class, () -> tokenizer.tokenizeString("\"string \n continued" ));
	}

	@Test
	public void testInvalidVerilogStyleNumber() {

		Tokenizer tokenizer = new Tokenizer();
		Assertions.assertThrows(ParseError.class, () -> tokenizer.tokenizeString("32'FF"));
	}

	@Test
	public void testTokenLeafParser() {

		Tokenizer tokenizer = new Tokenizer();
		Token[] tokens = tokenizer.tokenizeString("123 \\field \"The answer is... \\\"42\\\"!\"").tokens.toArray(Token[]::new);

		Assertions.assertEquals(123, tokens[0].asLong());
		Assertions.assertEquals("field", tokens[1].asString());
		Assertions.assertEquals("The answer is... \"42\"!", tokens[2].asString());
	}

	@Test
	public void testTokenizerAfterDetail() {

		Tokenizer tokenizer = new Tokenizer();
		ParseError error = Assertions.assertThrows(ParseError.class, () -> tokenizer.tokenizeString("valid_token $"));

		Assertions.assertEquals("Unexpected '$', after token 'valid_token' at line 1:13 in string \"valid_token $\"", error.getMessage());

	}

	@Test
	public void testTokenizerComments() {

		Tokenizer tokenizer = new Tokenizer();
		Assertions.assertEquals(0, tokenizer.tokenizeString("/* comment */").tokens.size());
		Assertions.assertEquals(0, tokenizer.tokenizeString("// comment").tokens.size());
		Assertions.assertEquals(0, tokenizer.tokenizeString("/* comment \n // still \n still \n*/\n").tokens.size());
	}

	@Test
	public void testInvalidComments() {

		Tokenizer tokenizer = new Tokenizer();
		Assertions.assertThrows(ParseError.class, () -> tokenizer.tokenizeString("/* comment "));
	}

	@Test
	public void testTokenizeRenodeRdlNoException() throws IOException {

		Tokenizer tokenizer = new Tokenizer();

		// here we just check if parseErrors are NOT thrown by the tokenizer
		tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/ABRTCMC.rdl"));
		tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/FT5336.rdl"));
		tokenizer.tokenizeFile(Resource.fromJavaResource(this, "/SAMD21_Timer.rdl"));

	}

}
