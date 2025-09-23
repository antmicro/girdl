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
package com.antmicro.girdl.model;

import org.apache.commons.lang3.builder.HashCodeBuilder;

public class Binding {

	public final Peripheral peripheral;
	public final String name;
	public final long address;
	private String description = "";

	public Binding(Peripheral peripheral, String name, long address) {
		this.peripheral = peripheral;
		this.name = name;
		this.address = address;
	}

	public void merge(Binding binding) {
		if (description.isBlank()) {
			description = binding.description;
		}
	}

	public Binding copyFor(Peripheral peripheral) {
		return new Binding(peripheral, name, address).setDescription(description);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Binding other) {
			return other.address == address && other.name.equals(name);
		}

		return false;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17, 37).append(name).append(address).toHashCode();
	}

	@Override
	public String toString() {
		final String suffix = peripheral.name.equals(name) ? "" : " (aka. '" + name + "')";
		return peripheral + suffix + " at 0x" + Long.toHexString(address);
	}

	public String getDescription() {
		return description;
	}

	public Binding setDescription(String description) {
		this.description = description;
		return this;
	}

}
