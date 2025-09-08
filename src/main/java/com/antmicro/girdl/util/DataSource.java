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
package com.antmicro.girdl.util;

import groovyjarjarantlr4.v4.runtime.misc.Nullable;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;

public final class DataSource {

	private final Set<String> sources = new TreeSet<>();

	public static DataSource of(String... strings) {
		return new DataSource().addSources(strings);
	}

	public DataSource addSources(String... strings) {
		Arrays.stream(strings).forEach(this::addSource);
		return this;
	}

	public DataSource addSource(@Nullable String source) {
		if (source != null && !source.isBlank()) {
			sources.add(source);
		}

		return this;
	}

	public Optional<String> primary() {
		return sources.stream().findFirst();
	}

	public void forEachNonPrimary(Consumer<String> consumer) {
		sources.stream().skip(1).forEachOrdered(consumer);
	}

}
