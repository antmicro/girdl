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

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.compiler.Param;
import com.antmicro.girdl.data.rdl.compiler.Scope;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.util.Lookup;

import java.util.function.Function;

public class ParametricType extends CompositeType {

	public static class Template implements Function<StructuredValue, ComponentType> {

		final ComponentKind kind;
		final Function<StructuredValue, ComponentType> factory;

		public Template(ComponentKind kind, Function<StructuredValue, ComponentType> factory) {
			this.kind = kind;
			this.factory = factory;
		}

		@Override
		public ComponentType apply(StructuredValue params) {
			return factory.apply(params);
		}

	}

	/**
	 * The type factory for the component that this is a parameterized view of,
	 * that is, upon implicitization this factory will be invoked to create a concrete type.
	 */
	private transient final Template template;

	/**
	 * List of all parameters that have been defined for this parametric type, some may
	 * have default values. parameter that are not present on this list will throw an exception when passed to implicitize().
	 */
	private final Lookup<Param> parameters = new Lookup<>();

	/**
	 * The name of the parametric type and the underlying template type should match, the
	 * template type factory will be invoked during implicitization (a call to implicitize()).
	 */
	public ParametricType(String name, Template template) {
		super(name);
		this.template = template;
	}

	/**
	 * Create a new type parameter, the optional initializer can be used to provide default
	 * value that will be resolved during object implicitization.
	 *
	 * @param provider Default value initializer, can be null
	 * @param location Source code location, can be null
	 */
	public void addParameter(String name, TypeValue type, Param.Init provider, Location location) {
		parameters.add(name, new Param(type, name, provider, location));
	}

	/**
	 * Check if the parametric type has no parameters - that is it can be elided back
	 * into to the basic template type without losing any information.
	 */
	public boolean isElidable() {
		return parameters.entries().isEmpty();
	}

	/**
	 * Check if this parametric type can be constructed without supplying any parameters,
	 * either due to it being easily elidable (see isElidable()) or having a default value for every parameter.
	 */
	public boolean isDefaultable() {
		return parameters.entries().values().stream().allMatch(Param::hasDefault);
	}

	/**
	 * Create the concrete type for of this parametric component by substituting parameters with provided values,
	 * some values may be omitted if the specific parameter has a default value provider. The given scope is passed to the provider if it is used.
	 */
	@Override
	public ComponentType implicitize(Scope scope, StructuredValue args) {
		StructuredValue combined = StructuredValue.empty();

		args.values.forEach((key, value) -> {
			Param fallback = parameters.getByName(key);

			// fallback value can not be null, as that would mean
			// the parameter hasn't been defined during type creation
			if (fallback == null) {
				throw ParseError.create(location).setDetail("Undefined parameter '." + key + "' referenced").build();
			}

			// before we write the value to the output set
			// cast it to the declared type to ensure correctness
			combined.values.put(key, fallback.type.instantiate(scope, value));
		});

		try {

			// default parameter values
			for (Param param : parameters.values()) {
				if (!combined.values.containsKey(param.name)) {
					combined.values.put(param.name, param.getDefault(scope).orElse(UnsetValue.UNSET));
				}
			}

		} catch (ParseError error) {
			error.append("Caused by implicitization at line " + args.location.where());
			throw error;
		}

		return template.apply(combined);
	}

	@Override
	public Value instantiate(Scope scope, Value rhs) {
		throw new RuntimeException("Parametric component '" + name + "' can't be directly instantiated!");
	}

	public ComponentKind getTemplateType() {
		return template.kind;
	}

}
