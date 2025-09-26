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
package com.antmicro.girdl.model.type;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class FunctionNode extends TypeNode {

	/// Return value, null if the function doesn't return.
	public TypeNode result;
	public final String name;
	public final List<Parameter> parameters = new ArrayList<>();

	public long low = 0;
	public long high = 0;

	private FunctionNode(TypeNode returnType, String name) {
		this.result = returnType;
		this.name = name;
	}

	public static FunctionNode of(TypeNode returnType, String name) {
		return new FunctionNode(returnType, name);
	}

	public void setCodeSpan(long low, long high) {
		this.low = low;
		this.high = high;
	}

	public void addParameter(String name, TypeNode type) {
		parameters.add(new Parameter(name, type));
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptFunction(this);
	}

	@Override
	public int size(int width) {
		return 0;
	}

	@Override
	public int hashCode() {
		return (result == null ? 0 : result.hashCode()) * 11 + parameters.hashCode() + name.hashCode() * 3 + Long.hashCode(low) * 7 + Long.hashCode(high) * 37;
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) return true;

		if (object instanceof FunctionNode other) {
			return Objects.equals(other.result, result) && other.name.equals(name) && other.parameters.equals(parameters) && other.low == low && other.high == high;
		}

		return false;
	}

	public boolean hasNoReturn() {
		return result == null;
	}

	public static class Parameter {

		public final String name;
		public final TypeNode type;

		public Parameter(String s, TypeNode type) {
			this.name = s;
			this.type = type;
		}

		@Override
		public int hashCode() {
			return name.hashCode() * 7 + type.hashCode();
		}

		@Override
		public boolean equals(Object object) {
			if (object == this) return true;

			if (object instanceof Parameter other) {
				return other.name.equals(name) && other.type.equals(type);
			}

			return false;
		}

	}

}
