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
package com.antmicro.girdl.data.svd;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SvdPeripherals {

	private transient Map<String, SvdPeripheral> lookup;
	public List<SvdPeripheral> peripheral;

	public SvdPeripheral byName(String name) {
		if (lookup == null) {
			lookup = new HashMap<>();

			peripheral.forEach(node -> {
				lookup.put(node.name, node);
			});
		}

		return lookup.get(name);
	}

}
