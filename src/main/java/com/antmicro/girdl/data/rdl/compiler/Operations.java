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
package com.antmicro.girdl.data.rdl.compiler;

import com.antmicro.girdl.data.rdl.compiler.model.PrimitiveValue;
import com.antmicro.girdl.data.rdl.compiler.model.Value;
import com.antmicro.girdl.util.UnimplementedException;

public class Operations {

	/*
	 * Binary operators
	 */

	public static Value logicalAnd(Value left, Value right) {
		return Value.of(left.toBool() && right.toBool());
	}

	public static Value logicalOr(Value left, Value right) {
		return Value.of(left.toBool() || right.toBool());
	}

	public static Value lessThan(Value left, Value right) {
		return Value.of(left.toLong() < right.toLong());
	}

	public static Value greaterEqual(Value left, Value right) {
		return Value.of(left.toLong() > right.toLong());
	}

	public static Value lessEqual(Value left, Value right) {
		return Value.of(left.toLong() <= right.toLong());
	}

	public static Value greaterThan(Value left, Value right) {
		return Value.of(left.toLong() >= right.toLong());
	}

	public static Value equal(Value left, Value right) {
		return Value.of(left.equals(right));
	}

	public static Value notEqual(Value left, Value right) {
		return Value.of(!left.equals(right));
	}

	public static Value shiftLeft(Value left, Value right) {
		return Value.of(left.toLong() << right.toLong());
	}

	public static Value shiftRight(Value left, Value right) {
		return Value.of(left.toLong() >> right.toLong());
	}

	public static Value power(Value left, Value right) {
		return Value.of((long) Math.pow(left.toLong(), right.toLong()));
	}

	public static Value multiply(Value left, Value right) {
		return Value.of(left.toLong() * right.toLong());
	}

	public static Value divide(Value left, Value right) {
		return Value.of(left.toLong() / right.toLong());
	}

	public static Value add(Value left, Value right) {
		return Value.of(left.toLong() + right.toLong());
	}

	public static Value subtract(Value left, Value right) {
		return Value.of(left.toLong() - right.toLong());
	}

	public static Value modulo(Value left, Value right) {
		return Value.of(left.toLong() % right.toLong());
	}

	public static Value binaryAnd(Value left, Value right) {
		return Value.of(left.toLong() & right.toLong());
	}

	public static Value binaryOr(Value left, Value right) {
		return Value.of(left.toLong() | right.toLong());
	}

	public static Value binaryXor(Value left, Value right) {
		return Value.of(left.toLong() ^ right.toLong());
	}

	public static Value binaryXnor(Value left, Value right) {
		return Value.of(~(left.toLong() ^ right.toLong()));
	}

	/*
	 * Unary operators
	 */

	public static Value binaryNot(Value value) {
		return Value.of(~value.toLong());
	}

	public static Value logicalNot(Value value) {
		return Value.of(!value.toBool());
	}

	public static Value negate(Value value) {
		return Value.of(-value.toLong());
	}

	public static Value ignore(Value value) {
		return value;
	}

	public static PrimitiveValue.BoolValue reduceAnd(Value value) {
		// TODO: add AND reduction (this will require the addition of sized types)
		throw UnimplementedException.ofSingular("Unary AND reduction operator");
	}

	public static PrimitiveValue.BoolValue reduceXor(Value value) {
		// TODO: add XOR reduction (this will require the addition of sized types)
		throw UnimplementedException.ofSingular("Unary XOR reduction operator");
	}

	public static PrimitiveValue.BoolValue reduceXnor(Value value) {
		// TODO: add XNOR reduction (this will require the addition of sized types)
		throw UnimplementedException.ofSingular("Unary XNOR reduction operator");
	}

	public static PrimitiveValue.BoolValue reduceNor(Value value) {
		return reduceOr(value).negate();
	}

	public static PrimitiveValue.BoolValue reduceNand(Value value) {
		return reduceAnd(value).negate();
	}

	public static PrimitiveValue.BoolValue reduceOr(Value value) {
		long bits = value.toLong();
		long low = (bits & 1);

		for (int i = 1; i < 64; i ++) {
			bits >>= 1;
			long high = (bits & 1);

			low = low | high;
		}

		return Value.of(low != 0);
	}


}
