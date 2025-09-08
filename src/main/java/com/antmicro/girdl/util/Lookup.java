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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class Lookup<T> {

	private final Map<String, T> map = new HashMap<>();
	private final List<T> list = new ArrayList<>();

	public void add(String key, T element) {
		list.add(element);
		map.put(key, element);
	}

	public void addAll(Lookup<T> registry) {
		map.putAll(registry.map);
		list.addAll(registry.list);
	}

	public List<T> values() {
		return list;
	}

	public Map<String, T> entries() {
		return map;
	}

	public T getByName(String key) {
		return map.get(key);
	}

}
