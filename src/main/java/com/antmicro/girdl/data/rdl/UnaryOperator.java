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
package com.antmicro.girdl.data.rdl;

import com.antmicro.girdl.data.rdl.compiler.Operations;
import com.antmicro.girdl.data.rdl.compiler.model.Value;
import com.antmicro.girdl.data.rdl.parser.TokenPredicate;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

public enum UnaryOperator {

	// this one has two valid lexemes (for some reason)
	// see the match() method for the other hardcoded one
	XNOR_REDUCTION("~^", Operations::reduceXnor),

	// long operators
	NAND_REDUCTION("~&", Operations::reduceNand),
	NOR_REDUCTION("~|", Operations::reduceNor),

	// short operators
	LOGICAL_NOT("!", Operations::logicalNot),
	PLUS("+", Operations::ignore),
	MINUS("-", Operations::negate),
	NOT("~", Operations::binaryNot),
	AND_REDUCTION("&", Operations::reduceAnd),
	OR_REDUCTION("|", Operations::reduceOr),
	XOR_REDUCTION("^", Operations::reduceXor);

	final String lexeme;
	final TokenPredicate predicate;
	final Function<Value, Value> operation;

	UnaryOperator(String lexeme, Function<Value, Value> operation) {
		this.lexeme = lexeme;
		this.predicate = TokenPredicate.of(lexeme);
		this.operation = operation;
	}

	public boolean match(TokenStream stream) {
		if (stream.match(predicate)) {
			return true;
		}

		// try matching the alternative spelling
		if (this == XNOR_REDUCTION) {
			return stream.match("^~");
		}

		return false;
	}

	public Value apply(Value input) {
		return operation.apply(input);
	}

	public static List<String> toLexemeList() {
		return Arrays.stream(values()).map(unary -> unary.lexeme).toList();
	}

}
