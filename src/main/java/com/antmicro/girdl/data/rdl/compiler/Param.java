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

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.compiler.model.TypeValue;
import com.antmicro.girdl.data.rdl.compiler.model.Value;
import groovyjarjarantlr4.v4.runtime.misc.Nullable;

import java.util.Optional;

public final class Param extends ModelNode {

	public final TypeValue type;
	public final String name;

	@Nullable
	private transient final Init provider;

	public Param(TypeValue type, String name, @Nullable Init provider, @Nullable Location location) {
		this.type = type;
		this.name = name;
		this.provider = provider;

		if (location != null) {
			this.location = location;
		}
	}

	public boolean hasDefault() {
		return provider != null;
	}

	public Optional<Value> getDefault(Scope scope) {
		if (!hasDefault()) {
			return Optional.empty();
		}

		return Optional.of(provider.getForParameterSet(scope));
	}

	@FunctionalInterface
	public interface Init {

		/**
		 * Applied at parametrization time for unset parameters to provide default values,
		 * the provided map contains all the symbols that are available in the scope of this expression.
		 */
		Value getForParameterSet(Scope scope);

	}

}
