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
package com.antmicro.girdl.export;

import com.antmicro.girdl.model.type.TypeNode;

import java.util.function.Predicate;

public enum DwarfExportGlobals {
	ALL("All symbols", type -> true),
	PERIPHERALS("Only peripherals", TypeNode::isPeripheral),
	NONE("No symbols", type -> false);

	final String description;
	final Predicate<TypeNode> predicate;

	DwarfExportGlobals(String description, Predicate<TypeNode> predicate) {
		this.description = description;
		this.predicate = predicate;
	}

	@Override
	public String toString() {
		return description;
	}

	boolean shouldInclude(TypeNode type) {
		return predicate.test(type);
	}
}
