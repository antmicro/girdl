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

import java.util.ArrayList;
import java.util.List;

public class DwarfExportConfig {

	public final long address;
	public final boolean variables;
	public final boolean parameters;
	public final boolean source;
	public final boolean types;
	public final boolean equates;
	public final DwarfExportGlobals globals;

	public DwarfExportConfig(long address, boolean variables, boolean parameters, boolean source, boolean types, boolean equates, DwarfExportGlobals globals) {
		this.address = address;
		this.variables = variables;
		this.parameters = parameters;
		this.source = source;
		this.types = types;
		this.equates = equates;
		this.globals = globals;
	}

	///  Check if running the decompiler will be necessary
	boolean shouldRunDecompiler() {
		return variables || parameters || source;
	}

	/// Check if a particular type should be included
	public boolean shouldExportSymbol(TypeNode type) {
		return globals.shouldInclude(type);
	}

	/// Check if this config orders no data to be created
	public boolean isEmpty() {
		return !(shouldRunDecompiler() || types || equates || globals != DwarfExportGlobals.NONE);
	}

	@Override
	public String toString() {
		List<String> options = new ArrayList<>(4);

		if (variables) options.add("variables");
		if (parameters) options.add("parameters");
		if (source) options.add("source");
		if (types) options.add("types");
		if (equates) options.add("equates");

		return "DwarfExportConfig{address: 0x" + Long.toHexString(address) + ", options: " + options + ", globals: " + globals.name() + "}";
	}
}
