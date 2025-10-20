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
package com.antmicro.girdl;

import com.antmicro.girdl.data.elf.LineProgrammer;
import com.antmicro.girdl.util.source.SourceFactory;
import com.antmicro.girdl.util.source.SourceLine;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class GhidraGlobalDecompiler {

	private final Program program;

	public GhidraGlobalDecompiler(Program program) {
		this.program = program;
	}

	public String dump(LineProgrammer programmer, long addend, String sourceFilename) {

		SourceFactory source = new SourceFactory();

		DecompileOptions opts = new DecompileOptions();
		opts.grabFromProgram(program);

		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(opts);
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(true);
		ifc.setSimplificationStyle("decompile");
		ifc.openProgram(program);

		FunctionIterator fit = program.getFunctionManager().getFunctions(true);
		TaskMonitor monitor = new DummyCancellableTaskMonitor();

		for (Function function : fit) {

			if (function.isExternal() || function.isThunk()) {
				continue;
			}

			DecompileResults res = ifc.decompileFunction(function, 30, monitor);

			// add a bit of spacing to make the source more readable
			source.addEmpty();
			source.addEmpty();
			String where = "0x" + Long.toHexString(function.getEntryPoint().getOffset());

			if (!res.decompileCompleted()) {
				source.addLine("// Failed to decompile " + where + ": " + res.getErrorMessage());
				continue;
			}

			source.addLine("// Decompiled from address " + where);
			appendSource(source, res);

		}

		int dir = programmer.addDirectory("./");
		programmer.setFile(dir, sourceFilename);
		programmer.setColumn(1);

		source.forEachMapped(line -> {

			long offset = line.address + addend;

			programmer.setLine(line.line);
			programmer.setAddress(offset);
			programmer.next();

		});

		programmer.advanceAddress(1);
		programmer.endSequence();

		return source.asSource();
	}

	private void appendSource(SourceFactory source, DecompileResults result) {

		StringBuilder line = new StringBuilder();
		long offset = result.getFunction().getEntryPoint().getOffset();

		List<ClangNode> tokens = new ArrayList<>();
		result.getCCodeMarkup().flatten(tokens);

		for (ClangNode node : tokens) {
			line.append(node.toString());

			if (node instanceof ClangBreak breakNode) {
				if (line.isEmpty()) {
					continue;
				}

				source.addLine(line.toString(), offset);

				line.setLength(0);
				line.repeat("  ", breakNode.getIndent());
			}

			Address address = node.getMinAddress();

			if (address != null) {
				offset = address.getOffset();
			}

		}
	}

}
