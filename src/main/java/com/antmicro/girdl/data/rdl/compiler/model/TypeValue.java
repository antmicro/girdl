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
package com.antmicro.girdl.data.rdl.compiler.model;

import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.compiler.Scope;
import groovyjarjarantlr4.v4.runtime.misc.Nullable;

import java.util.Collections;
import java.util.Map;

/**
 * The shared root of the class tree for all RDL types.
 */
public abstract class TypeValue extends Value {

	public static final TypeValue TYPE = new PureTypeValue();

	public final String name;

	protected TypeValue(String name) {
		this.name = name;
	}

	@Override
	public TypeValue getType() {
		return TYPE;
	}

	/**
	 * Query type by name.
	 */
	public @Nullable TypeValue getType(String name) {
		return types().get(name);
	}

	/**
	 * Helper for use outside the RDL compiler, create a context-less instance of a type.
	 */
	public Value create() {
		return instantiate(Scope.empty(), UnsetValue.UNSET);
	}

	/**
	 * For all types but the ParametricType this will throw for args.size() > 0.
	 */
	public TypeValue implicitize(Scope scope, StructuredValue args) {
		if (!args.values.isEmpty()) {
			ParseError.create(location).setDetail("Cannot implicitize a non-parametric type!").raise();
		}

		return this;
	}

	/**
	 * Create an instance of this type using the rhs value as the initializer.
	 */
	public abstract Value instantiate(Scope scope, Value rhs);

	/**
	 * Get a list of types defined within this type, for all but the ComponentType this will be an empty map.
	 */
	public Map<String, TypeValue> types() {
		return Collections.emptyMap();
	}

	/**
	 * The type of all type values, used by all classes derived from TypeValue.
 	 */
	private static final class PureTypeValue extends TypeValue {

		PureTypeValue() {
			super("type");
		}

		@Override
		public Value instantiate(Scope scope, Value rhs) {
			return this;
		}

	}

}
