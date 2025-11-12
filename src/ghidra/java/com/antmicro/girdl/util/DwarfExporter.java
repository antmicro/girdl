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
package com.antmicro.girdl.util;

import com.antmicro.girdl.GhidraGlobalDecompiler;
import com.antmicro.girdl.adapter.GirdlTypeAdapter;
import com.antmicro.girdl.data.elf.DwarfFile;
import com.antmicro.girdl.data.elf.LineProgrammer;
import com.antmicro.girdl.data.elf.Storage;
import com.antmicro.girdl.data.elf.enums.ElfMachine;
import com.antmicro.girdl.data.elf.source.SourceFactory;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.util.log.Logger;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.util.Iterator;
import java.util.function.Function;

public final class DwarfExporter extends DwarfFile {

	private DwarfExporter(File file, Program program) {
		super(file, ArchitectureFinder.guessElfMachine(program, ElfMachine.NONE), program.getDefaultPointerSize() * 8);
	}

	public static void dumpProgramDebugInfo(File dwarf, Program program, long offset) {
		try (DwarfExporter exporter = new DwarfExporter(dwarf, program)) {
			GirdlTypeAdapter adapter = new GirdlTypeAdapter();

			GhidraGlobalDecompiler decompiler = new GhidraGlobalDecompiler(program);

			SourceFactory source = decompiler.dump(adapter, offset);
			source.saveSource(dwarf.getAbsolutePath() + ".c");

			LineProgrammer programmer = exporter.createLineProgram();
			int dir = programmer.addDirectory("./");
			programmer.setFile(dir, dwarf.getName() + ".c");
			programmer.setColumn(1);

			programmer.encodeSource(source, offset);
			programmer.advanceAddress(1);
			programmer.endSequence();

			exporter.createDebugFromProgram(program, offset, decompiler, adapter);
		}
	}

	private static TypeNode getTypeFromData(Function<Object, TypeNode> converter, Data data) {

		if (data == null) {
			return null;
		}

		if (Undefined.isUndefined(data.getDataType())) {
			int size = data.getDataType().getLength();

			if (size == 0) {
				return BaseNode.BYTE;
			}

			return BaseNode.of(size);
		}

		return converter.apply(data.getDataType());

	}

	public void createDebugFromProgram(Program program, long offset, FunctionDetailProvider provider, GirdlTypeAdapter adapter) {

		final Function<Object, TypeNode> converter = adapter.getTypeConverter();

		/*
		 * First convert and save all data types that we know of
		 * not all of them will have a symbol but there is no reason to omit those.
		 */

		Iterator<DataType> types = program.getDataTypeManager().getAllDataTypes();

		while (types.hasNext()) {
			createType(converter.apply(types.next()));
		}

		/*
		 * Next, we add all symbols (global variables, etc.) and their types (if
		 * not yet seen before), we do hover skip some of them, mainly assembly labels (by
		 * the fact they have a null type).
		 */

		SymbolIterator symbols = program.getSymbolTable().getAllSymbols(true);

		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			Address address = symbol.getAddress();

			if (symbol.isExternal()) {
				Logger.debug(this, "Skipping external symbol: " + symbol.getName());
				continue;
			}

			TypeNode type = getTypeFromData(converter, program.getListing().getDataAt(address));

			if (type == null) {
				Logger.debug(this, "Skipping untyped symbol: " + symbol.getName());
				continue;
			}

			createGlobalVariable(type, symbol.getName(), Storage.ofAddress(address.getOffset() + offset));
		}

		/*
		 * Equates are a type of constant that can be used for numeric values in the code
		 * they are resolved by Ghidra in all places in the code automatically (any use of
		 * the equated value turns to a use of the equate).
		 */

		Iterator<Equate> equates = program.getEquateTable().getEquates();

		while (equates.hasNext()) {
			Equate equate = equates.next();
			createGlobalVariable(BaseNode.LONG, equate.getName(), Storage.ofConst(equate.getValue()));
		}

		/*
		 * And finally, we handle functions, they work a bit differently and have no DataType attached,
		 * that's why our type converter accepts objects, from a Ghidra Function we can extract the FunctionSignature
		 * that we convert to FunctionNode, and then add the address information after the conversion. Some function
		 * types may have already been created in the first step if some function pointer is being used somewhere,
		 * if so, they will get deduplicated by the DWARF encoder itself.
		 */

		FunctionIterator functions = program.getFunctionManager().getFunctions(true);

		while (functions.hasNext()) {

			// ghidra uses a somewhat terrible name 'Function' for the type here
			// so we have to avoid specifying it directly here
			var function = functions.next();

			if (function.isLibrary() || function.isExternal()) {
				Logger.debug(DwarfExporter.class, "Skipping external function: " + function.getName());
				continue;
			}

			if (function.isThunk()) {
				Logger.debug(DwarfExporter.class, "Skipping thunk function: " + function.getName());
				continue;
			}

			final Address address = function.getEntryPoint();
			final TypeNode node = converter.apply(function.getSignature(true));

			// no other type realistically should be returned here,
			// but we need to cast and verify if it is null anyway
			if (node instanceof FunctionNode functionNode) {

				provider.getFunctionDetails(function).ifPresent(info -> {
					functionNode.variables.clear();
					functionNode.variables.addAll(info.locals);
				});

				long start = address.getOffset() + offset;
				long end = start + function.getBody().getNumAddresses();

				// without specifying the range debuggers will ignore this function
				// (start address is not enough for GDB)
				functionNode.setCodeSpan(start, end);
				createType(functionNode);
			}
		}
	}

}
