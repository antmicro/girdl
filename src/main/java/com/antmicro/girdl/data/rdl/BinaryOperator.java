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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiFunction;

/**
 * Used by both the parser and lexer.
 * Long operators need to be placed before the short ones for the
 * tokenizer to detect them as it will emit the first one matched in the list.
 */
public enum BinaryOperator {

	// this one has two valid lexemes (for some reason)
	// see the match() method for the other hardcoded one
	BITWISE_XNOR(40, "~^", Operations::binaryXnor),

	// long operators
	AND(20, "&&", Operations::logicalAnd),
	OR(10, "||", Operations::logicalOr),
	LESS_THAN(70, "<", Operations::lessThan),
	GREATER_THAN(70, ">", Operations::greaterThan),
	LESS_OR_EQUAL(70, "<=", Operations::lessEqual),
	GREATER_OR_EQUAL(70, ">=", Operations::greaterEqual),
	EQUAL(60, "==", Operations::equal),
	NOT_EQUAL(60, "!=", Operations::notEqual),
	SHIFT_RIGHT(80, ">>", Operations::shiftRight),
	SHIFT_LEFT(80, "<<", Operations::shiftLeft),
	POWER(100, "**", Operations::power),

	// short operators
	BITWISE_AND(50, "&", Operations::binaryAnd),
	BITWISE_OR(30, "|", Operations::binaryOr),
	BITWISE_XOR(40, "^", Operations::binaryXor),
	MULTIPLY(100, "*", Operations::multiply),
	DIVIDE(100, "/", Operations::divide),
	MODULO(100, "%", Operations::modulo),
	PLUS(90, "+", Operations::add),
	MINUS(90, "-", Operations::subtract);

	final int precedence;
	final String lexeme;
	final TokenPredicate predicate;
	final BiFunction<Value, Value, Value> operation;

	BinaryOperator(int precedence, String lexeme, BiFunction<Value, Value, Value> operation) {
		this.precedence = precedence;
		this.lexeme = lexeme;
		this.predicate = TokenPredicate.of(lexeme);
		this.operation = operation;
	}

	public boolean match(TokenStream stream) {
		if (stream.match(predicate)) {
			return true;
		}

		// try matching the alternative spelling
		if (this == BITWISE_XNOR) {
			return stream.match("^~");
		}

		return false;
	}

	public Value apply(Value left, Value right) {
		return operation.apply(left, right);
	}

	public static List<List<BinaryOperator>> toPrecedenceArrays() {
		Map<Integer, List<BinaryOperator>> mapped = new TreeMap<>();

		for (BinaryOperator type : values()) {
			mapped.computeIfAbsent(type.precedence, key -> new ArrayList<>()).add(type);
		}

		return mapped.values().stream().toList();
	}

	public static List<String> toLexemeList() {
		return Arrays.stream(values()).map(unary -> unary.lexeme).toList();
	}

}
