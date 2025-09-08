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

import java.util.Iterator;

public final class IndexedIterator<T> implements Iterable<IndexedIterator.Entry<T>>, Iterator<IndexedIterator.Entry<T>> {

	private final Iterator<T> base;
	private int index = 0;

	public IndexedIterator(Iterator<T> base) {
		this.base = base;
	}

	public static <T> IndexedIterator<T> of(Iterable<T> base) {
		return new IndexedIterator<>(base.iterator());
	}

	@Override
	public boolean hasNext() {
		return base.hasNext();
	}

	@Override
	public Entry<T> next() {
		return new Entry<>(index ++, base.next());
	}

	@Override
	public Iterator<Entry<T>> iterator() {
		return this;
	}

	public record Entry<T> (int index, T value) {}

}
