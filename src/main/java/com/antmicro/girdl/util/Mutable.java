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

import java.util.function.Function;

public final class Mutable<T> {

	public T value;

	private Mutable(T value) {
		this.value = value;
	}

	/**
	 * Construct a new mutable object reference.
	 */
	public static <T> Mutable<T> wrap(T value) {
		return new Mutable<>(value);
	}

	/**
	 * Replace the value held by this mutable using the given lambda.
	 */
	public Mutable<T> map(Function<T, T> mapper) {
		value = mapper.apply(value);
		return this;
	}

	public <R> R to(Function<T, R> mapper) {
		return mapper.apply(value);
	}

}
