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

import com.antmicro.girdl.adapter.GirdlTypeAdapter;
import com.antmicro.girdl.data.elf.Storage;
import com.antmicro.girdl.data.elf.source.SourceFactory;
import com.antmicro.girdl.data.elf.storage.StaticStorage;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.util.DwarfRegistryResolver;
import com.antmicro.girdl.util.FunctionDetailProvider;
import com.antmicro.girdl.util.log.Logger;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.DummyCancellableTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class GhidraGlobalDecompiler implements FunctionDetailProvider {

	private boolean debugPrintPCode = false;
	private final Program program;
	private final Map<Function, FunctionInfo> functions = new HashMap<>();

	public GhidraGlobalDecompiler(Program program) {
		this.program = program;
	}

	public SourceFactory dump(GirdlTypeAdapter adapter, long offset) {

		DwarfRegistryResolver registers = new DwarfRegistryResolver(program.getLanguage());
		SourceFactory source = new SourceFactory();
		var converter = adapter.getTypeConverter();

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

			final long functionStartAddress = function.getEntryPoint().getOffset();
			final long functionEndAddress = functionStartAddress + function.getBody().getNumAddresses();

			String where = "0x" + Long.toHexString(functionStartAddress);

			if (!res.decompileCompleted()) {
				source.addLine("// Failed to decompile " + where + ": " + res.getErrorMessage());
				continue;
			}

			if (debugPrintPCode) {
				PcodeUtils.dump(res.getHighFunction());
			}

			final LocalSymbolMap map = res.getHighFunction().getLocalSymbolMap();
			final List<FunctionNode.Variable> locals = new ArrayList<>();
			final var initials = PcodeUtils.toVarnodeRangeMap(res.getHighFunction().getPcodeOps());

			map.getSymbols().forEachRemaining(symbol -> {

				for (Varnode varnode : symbol.getStorage().getVarnodes()) {

					final Address address = varnode.getAddress();
					final StaticStorage varnodeStorage;

					if (varnode.isConstant()) {
						varnodeStorage = Storage.ofConst(varnode.getOffset());
					} else if (varnode.isRegister()) {
						varnodeStorage = Storage.ofDwarfRegister(registers.getDwarfRegister(program.getRegister(varnode)));
					} else if (address.isStackAddress()) {
						varnodeStorage = Storage.ofStack(address.getOffset() - address.getPointerSize());
					} else {

						// unsupported storage, completely skip this variable from output
						Logger.warn(this, "Unknown storage for varnode " + symbol.getName() + ": " + varnode + ", from function '" + function.getName() + "'");
						continue;
					}

					var range = initials.getRangeFor(varnode.getAddress()).orElse(PcodeUtils.INVARIANT);
					Storage storage = range.wrap(symbol, varnodeStorage, functionStartAddress, functionEndAddress, offset);

					locals.add(new FunctionNode.Variable(symbol.getName(), converter.apply(symbol.getDataType()), storage, symbol.isParameter()));

				}
			});

			functions.put(function, new FunctionInfo(Collections.unmodifiableList(locals)));

			source.addLine("// Decompiled from address " + where);
			appendSource(source, res);

		}

		return source;
	}

	private void appendSource(SourceFactory source, DecompileResults result) {

		StringBuilder line = new StringBuilder();

		boolean first = true;
		long prevOffset = 0;
		long nextOffset = result.getFunction().getEntryPoint().getOffset();

		List<ClangNode> tokens = new ArrayList<>();
		result.getCCodeMarkup().flatten(tokens);

		for (ClangNode node : tokens) {
			line.append(node.toString());
			Address address = node.getMinAddress();

			if (address != null) {
				long offset = address.getOffset();

				// we want to only select the address if we have nothing yet (first), of we found an
				// earlier address, that can occur at any point so we must be ready to go back.
				if (offset > prevOffset) {
					if (first || (offset < nextOffset)) {
						nextOffset = offset;
						first = false;
					}
				}
			}

			if (node instanceof ClangBreak breakNode) {
				if (line.isEmpty()) {
					continue;
				}

				source.addLine(line.toString(), nextOffset);
				prevOffset = nextOffset;
				first = true;

				line.setLength(0);
				line.repeat("  ", breakNode.getIndent());
			}
		}
	}

	@Override
	public Optional<FunctionInfo> getFunctionDetails(Function ghidraFunction) {
		final FunctionInfo info = functions.get(ghidraFunction);
		Logger.info(this, "Requested details for function: '" + ghidraFunction.getName() + "', " + (info == null ? "no data available" : "found " + info.locals.size() + " local variables"));
		return Optional.ofNullable(info);
	}

	/**
	 * Enable debug printing of PCode for each decompiled function.
	 */
	public void enablePCodePrinter() {
		this.debugPrintPCode = true;
	}

}
