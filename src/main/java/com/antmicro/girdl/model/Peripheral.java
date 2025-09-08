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

import com.antmicro.girdl.util.ComparisonResult;
import com.antmicro.girdl.util.Functional;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.UniversalIdGenerator;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Peripheral {

	public String name;
	private String description = "";
	public final List<Binding> bindings = new ArrayList<>();
	public final List<Register> registers = new ArrayList<>();
	private StructureDataType type = null;

	public Peripheral(String name) {
		this.name = name;
	}

	public Binding createBinding(String name, long address) {
		return Functional.append(bindings, new Binding(this, getNextUniqueName(name), address));
	}

	public Optional<Register> createRegister(String name, long offset, int bits) {
		for (Register existing : registers) {
			if (existing.offset == offset && (existing.getSize() * 8) == bits) {
				if (!name.equals(existing.name)) {
					Msg.info(this, "Looks like the register '" + name + "' in peripheral " + this.name + " is just an alias for '" + existing.name + "' as both start at 0x" + Long.toHexString(offset));
					existing.addAlias(name);
				}

				return Optional.empty();
			}
		}

		return Optional.of(Functional.append(registers, new Register(name, offset).setBits(bits)));
	}

	public void compile() {

		// this is needed to avoid exceptions being thrown in tests
		UniversalIdGenerator.initialize();

		List<Register> sorted = registers.stream().sorted().toList();
		tryDeducingMissingRegisterSizes(sorted);

		type = new StructureDataType(name, 0);
		int offset = 0;
		Register previous = null;

		for (Register register : sorted) {
			DataType field = register.getType();

			if (offset > register.offset) {
				String previousString = (previous == null ? "<error: no previous>" : previous.toQualifiedString());
				Msg.error(this, "The type for peripheral '" + name + "' can be malformed, as the register " + register.toQualifiedString() + " starts before the end of the previous register " + previousString + "'!");
				offset = Math.toIntExact(register.offset);
			}

			if (offset < register.offset) {
				long padding = register.offset - offset;
				type.add(new ArrayDataType(ByteDataType.dataType, (int) padding), "pad_" + padding, "Padding deduced from register offsets");
				offset += (int) padding;
			}

			type.add(register.getType(), register.name, register.getDescription());
			previous = register;

			offset += field.getLength();
		}
	}

	private void tryDeducingMissingRegisterSizes(List<Register> sorted) {
		Register previous = null;

		for (Register register : sorted) {
			if (previous != null && previous.isSizeMissing()) {
				int distance = (int) (register.offset - previous.offset);

				if (distance == 1 || distance == 2 || distance == 4 || distance == 8) {
					previous.setBytes(distance);
				}
			}

			previous = register;
		}
	}

	public ComparisonResult compareTypes(Object other) {
		if (other instanceof Peripheral right) {
			if (right.registers.isEmpty() || registers.isEmpty()) {
				return ComparisonResult.same();
			}

			if (registers.size() != right.registers.size()) {
				return ComparisonResult.different("peripherals have a different register count");
			}

			List<Register> leftRegisters = registers.stream().sorted().toList();
			List<Register> rightRegisters = right.registers.stream().sorted().toList();

			for (int i = 0; i < leftRegisters.size(); i ++) {
				 if (!leftRegisters.get(i).equals(rightRegisters.get(i))) {
					 return ComparisonResult.different("register '" + leftRegisters.get(i).name + "' differs in second definition");
				 }
			}

			return ComparisonResult.same();
		}

		return ComparisonResult.different("second object is not a peripheral");
	}

	public void merge(Peripheral other) {
		List<Binding> pending = new ArrayList<>();

		if (registers.isEmpty()) {
			registers.addAll(other.registers);
		}

		if (!description.equals(other.description)) {
			description += other.description;
		}

		for (Binding binding : other.bindings) {
			int index = bindings.indexOf(binding);

			if (index == -1) {
				pending.add(binding.copyFor(this));
				continue;
			}

			bindings.get(index).merge(binding);
		}

		bindings.addAll(pending);
	}

	public DataType getType() {
		return type;
	}

	@Override
	public String toString() {
		return name;
	}

	private String getNextUniqueName(String name) {
		boolean duplicate = false;
		String unique = name;
		int index = 1;

		while (true) {
			for (Binding binding : bindings) {
				if (binding.name.equals(unique)) {
					duplicate = true;
					break;
				}
			}

			if (!duplicate) {
				return unique;
			}

			unique = name + "_" + index;
			duplicate = false;
			index ++;
		}
	}

	public void addDescription(String part) {

		if (part.isBlank()) {
			return;
		}

		if (description.contains(part)) {
			return;
		}

		if (!description.isBlank()) {
			if (description.endsWith(".") || description.endsWith("!")) {
				description += " ";
			} else if (!description.endsWith(". ") && !description.endsWith("! ")) {
				description += ". ";
			}
		}

		description += part;
	}

	public String getDescription() {

		if (!description.isEmpty()) {
			return description;
		}

		final List<String> descriptions = bindings.stream().map(Binding::getDescription).filter(string -> !string.isBlank()).toList();
		boolean allEqual = descriptions.stream().distinct().limit(2).count() <= 1;

		if (descriptions.isEmpty()) {
			return "Peripheral Device - No Description";
		}

		if (allEqual) {
			return descriptions.getFirst();
		}

		return "Peripheral Device";

	}


	/**
	 * Check if the peripheral has no attached registers.
	 */
	public boolean hasNoRegisters() {
		return registers.isEmpty();
	}

	/**
	 * Check if the peripheral has no attached bindings or registers and can be safely ignored during import.
	 */
	public boolean isDisposable() {
		return hasNoRegisters() && bindings.isEmpty();
	}

}
