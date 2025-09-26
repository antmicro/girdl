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
package com.antmicro.girdl.data;

import com.antmicro.girdl.data.rdl.Macro;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.util.ComparisonResult;
import com.antmicro.girdl.util.log.Logger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class Context {

	private final Map<String, Peripheral> peripherals = new HashMap<>();
	public List<Macro> macros = List.of();

	/**
	 * Add the given peripheral to the context if it has a unique name,
	 * otherwise it tries to merge it (that is - gather additional bind points and
	 * copy descriptions) into the existing peripheral of the same type (that is
	 * same registers with same names at the same offsets). If no peripheral shares a type
	 * then the unique name is used and the peripheral gets added under a new name.
	 * If a unique name was not provided at this point the peripheral is ignored
	 * and will not be added to the context.
	 *
	 * @param peripheral The peripheral to add or merge into the context
	 * @param fallbackUniqueName Optional, alternative name for the peripheral if all else fails
	 */
	public void addPeripheral(Peripheral peripheral, Optional<String> fallbackUniqueName) {
		Peripheral other = peripherals.get(peripheral.name);

		// no name collision has occurred, this is the first binding of a peripheral (in SVD) or a new peripheral
		if (other == null) {
			peripherals.put(peripheral.name, peripheral);
			return;
		}

		// bail out early as we don't want to be merging an empty structs into each other to keep the logs understandable
		if (peripheral.isDisposable()) {
			Logger.trace(this, "Ignoring empty peripheral '" + peripheral.name);
			return;
		}

		// the duplicated peripherals are of the same type and can be merged
		ComparisonResult result = other.compareTypes(peripheral);

		if (result.same) {
			other.merge(peripheral);
			Logger.trace(this, "Merged new peripheral into '" + peripheral.name + "'");
			return;
		}

		// first try to guess the correct peripheral type, to reduce duplicate creation
		for (Peripheral candidate : peripherals.values()) {
			if (!candidate.registers.isEmpty() && candidate.compareTypes(peripheral).same) {
				candidate.merge(peripheral);
				Logger.trace(this, "Merged new peripheral into matching peripheral named '" + peripheral.name + "'");
				return;
			}
		}

		String duplicate = "Found another peripherals named '" + peripheral.name + "' with differing definition (" + result.message + ")";

		if (fallbackUniqueName.isEmpty()) {
			Logger.error(this, duplicate + ", as fallback unique name was not provided the peripheral will be dropped");
			return;
		}

		// if we got here we need to use the binding name and create a separate peripheral
		Logger.error(this, duplicate + ", using the fallback unique binding name '" + fallbackUniqueName.get() + "'!");
		peripheral.name = fallbackUniqueName.get();
		peripherals.put(peripheral.name, peripheral);
	}

	public Peripheral createPeripheral(String name) {
		return peripherals.computeIfAbsent(name, Peripheral::new);
	}

	public void compile() {
		peripherals.values().forEach(Peripheral::compile);
	}

	public Map<String, Peripheral> getPeripheralMap() {
		return peripherals;
	}

}
