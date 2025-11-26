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

import com.antmicro.girdl.adapter.GirdlTypeAdapter;
import com.antmicro.girdl.data.elf.Storage;
import com.antmicro.girdl.data.elf.source.SourceFactory;
import com.antmicro.girdl.data.elf.storage.StaticStorage;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.TypeNode;
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
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
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
	private final DwarfRegistryResolver registers;
	private final Map<Function, FunctionInfo> functions = new HashMap<>();

	// We need to use the full class name here as Ghidra had the great idea
	// of reusing names from the Java Standard Library and now there are import conflicts
	private final java.util.function.Function<Object, TypeNode> converter;

	public GhidraGlobalDecompiler(Program program, GirdlTypeAdapter adapter) {
		this.program = program;
		this.registers = new DwarfRegistryResolver(program.getLanguage());
		this.converter = adapter.getTypeConverter();
	}

	public static class FunctionRange {
		public final Function function;
		public final long start;
		public final long end;

		public FunctionRange(Function function, long startAddress, long endAddress) {
			this.function = function;
			this.start = startAddress;
			this.end = endAddress;
		}

		public static FunctionRange of(Function function) {
			final long start = function.getEntryPoint().getOffset();
			final long length = function.getBody().getNumAddresses();

			return new FunctionRange(function, start, start + length);
		}

		public String where() {
			return "0x" + Long.toHexString(start);
		}
	}

	private Storage wrapVarnodeStorage(PcodeUtils.RangeMap ranges, Address address, HighSymbol symbol, StaticStorage storage, FunctionRange info, long offset) {
		return storage.isUseSiteInvariant() ? storage : ranges.getRangeFor(address).orElse(PcodeUtils.INVARIANT).wrap(symbol, storage, info.start, info.end, offset);
	}

	private Optional<FunctionNode.Variable> processVarnode(Varnode varnode, HighSymbol symbol, FunctionRange info, PcodeUtils.RangeMap ranges, long offset) {

		final Address address = varnode.getAddress();
		final StaticStorage storage;

		if (varnode.isConstant()) {
			storage = Storage.ofConst(varnode.getOffset());
		} else if (varnode.isRegister()) {
			storage = Storage.ofDwarfRegister(registers.getDwarfRegister(program.getRegister(varnode)));
		} else if (address.isStackAddress()) {
			storage = Storage.ofStack(address.getOffset() - address.getPointerSize());
		} else if (varnode.isAddress()) {
			storage = Storage.ofAddress(address.getOffset());
		} else {
			// unsupported storage, completely skip this variable from output
			Logger.warn(this, "Unknown storage for varnode " + symbol.getName() + ": " + PcodeUtils.varnodeToString(varnode) + ", from function '" + info.function.getName() + "'");
			return Optional.empty();
		}

		return Optional.of(new FunctionNode.Variable(symbol.getName(), converter.apply(symbol.getDataType()), wrapVarnodeStorage(ranges, address, symbol, storage, info, offset), symbol.isParameter()));

	}

	private void processResults(Function function, DecompileResults res, SourceFactory source, long offset) {

		// add a bit of spacing to make the source more readable
		source.addEmpty();
		source.addEmpty();

		final FunctionRange info = FunctionRange.of(function);

		if (!res.decompileCompleted()) {
			source.addLine("// Failed to decompile " + info.where() + ": " + res.getErrorMessage());
			return;
		}

		if (debugPrintPCode) {
			PcodeUtils.dump(res.getHighFunction());
		}

		final HighFunction high = res.getHighFunction();
		final LocalSymbolMap map = high.getLocalSymbolMap();
		final List<FunctionNode.Variable> locals = new ArrayList<>();
		final PcodeUtils.RangeMap ranges = PcodeUtils.toVarnodeRangeMap(high);

		// process parameters and local variables
		map.getSymbols().forEachRemaining(symbol -> {
			for (Varnode varnode : symbol.getStorage().getVarnodes()) {
				try {
					processVarnode(PcodeUtils.findAlternativeVarnode(varnode, high), symbol, info, ranges, offset).ifPresent(locals::add);
				} catch (Exception e) {
					Logger.error(this, "Failed to process local symbol: " + symbol.getName() + ", for: " + function.getName() + ", " + e.getMessage());
				}
			}
		});

		functions.put(function, new FunctionInfo(Collections.unmodifiableList(locals)));

		source.addLine("// Decompiled from address " + info.where());
		appendSource(source, res);

	}

	public SourceFactory dump(DwarfExportConfig config, TaskMonitor monitor) {

		final long offset = config.address;
		functions.clear();

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
		TaskMonitor c = new DummyCancellableTaskMonitor();

		int total = program.getFunctionManager().getFunctionCount();
		monitor.setMaximum(total);

		for (Function function : fit) {
			monitor.incrementProgress();

			if (function.isExternal() || function.isThunk()) {
				continue;
			}

			final DecompileResults res = ifc.decompileFunction(function, 30, c);

			try {
				processResults(function, res, source, offset);
			} catch (Exception e) {
				Logger.error(this, "Failed to process function decompilation result for: " + function.getName() + ", " + e.getMessage());
			}
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
