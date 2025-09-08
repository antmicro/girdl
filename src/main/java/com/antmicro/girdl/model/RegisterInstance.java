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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

@Deprecated
public class RegisterInstance {

	private static final boolean UNIT_BYTES = false;

	public final Binding binding;
	public final Register register;

	public RegisterInstance(Binding binding, Register register) {
		this.binding = binding;
		this.register = register;
	}

	public Peripheral getPeripheral() {
		return binding.peripheral;
	}

	public long getAbsoluteOffset() {
		return register.offset + binding.address;
	}

	public Address getAddress(Program program) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(getAbsoluteOffset(), UNIT_BYTES);
	}

	public String getIdentifier() {
		return binding.name.isEmpty() ? register.toString() : binding.name + "::" + register;
	}

	@Override
	public String toString() {
		return getIdentifier() + " at 0x" + Long.toHexString(getAbsoluteOffset());
	}
}
