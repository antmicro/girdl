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

import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.stream.Stream;

public final class Functional {

	/**
	 * Implements the missing "fold left" operation on java streams.
	 *
	 * @param stream stream to fold using the reducer
	 * @param initial starting value that will be appended to
	 * @param reducer function to append elements to the initial value
 	 */
	public static <T, R> R fold(Stream<T> stream, R initial, BiFunction<R, T, R> reducer) {
		Mutable<R> wrapper = Mutable.wrap(initial);

		stream.forEachOrdered(element -> {
			wrapper.map(previous -> reducer.apply(previous, element));
		});

		return wrapper.value;
	}

	/**
	 * Computes the cartesian product of two sets.
	 *
	 * @param left first set
	 * @param right second set
	 */
	public static <A, B> Stream<Pair<A, B>> cartesian(Collection<A> left, Collection<B> right) {
		return left.stream().flatMap(a -> right.stream().map(b -> Pair.of(a, b)));
	}

	/**
	 * Appends the element to a collection and pass it along by returning it, similarly to StringBuilder::append().
	 *
	 * @param collection collection to expand
	 * @param value the element to append
	 */
	public static <T> T append(Collection<T> collection, T value) {
		collection.add(value);
		return value;
	}

	/**
	 * Creates a list from contents of multiple lists by merging them all together.
	 *
	 * @param lists lists to merge
	 * @return merged list
	 */
	@SafeVarargs
	public static <T> List<T> mergedList(List<T>... lists) {
		List<T> merged = new ArrayList<>();

		for (List<T> list : lists) {
			merged.addAll(list);
		}

		return merged;
	}

	/**
	 * Wraps a potenty throwing lambda into an optional return value.
	 *
	 * @param supplier Potentially throwing lambda
	 * @return Optional of result or empty optional if the supplier threw an exception
	 */
	public static <T> Optional<T> except(ThrowingSupplier<T> supplier) {
		try {
			return Optional.of(supplier.get());
		} catch (Throwable t) {
			return Optional.empty();
		}
	}

}
