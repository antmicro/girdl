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

import java.util.HashMap;
import java.util.Map;

public class BaseNode extends TypeNode {

	private static final Map<Integer, BaseNode> CACHE = new HashMap<>();
	public static final BaseNode BYTE = of(1);

	public final int bytes;

	public BaseNode(int bytes) {
		this.bytes = bytes;
	}

	public static BaseNode of(int bytes) {
		return CACHE.computeIfAbsent(bytes, BaseNode::new);
	}

	@Override
	public int hashCode() {
		return bytes;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof BaseNode base) {
			return base.bytes == bytes;
		}

		return false;
	}

	@Override
	public int size() {
		return bytes;
	}

	@Override
	public String toString() {
		return "uint" + (bytes * 8) + "_t";
	}

	@Override
	public <T> T adapt(Adapter<T> adapter) {
		return adapter.adaptBase(this);
	}

	public boolean isOfIntegralSize() {
		return bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8;
	}

}
