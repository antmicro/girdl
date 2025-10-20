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
import com.antmicro.girdl.data.elf.DwarfFile;
import com.antmicro.girdl.data.elf.enums.ElfMachine;
import com.antmicro.girdl.data.elf.enums.ElfSymbolFlag;
import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.model.type.UnionNode;
import com.antmicro.girdl.util.log.Logger;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DefaultDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

public final class DwarfExporter extends DwarfFile {

	private DwarfExporter(File file, Program program) {
		super(file, ArchitectureFinder.guessElfMachine(program, ElfMachine.NONE), program.getDefaultPointerSize() * 8);
	}

	public static void dumpProgramDebugInfo(File dwarf, Program program, long offset) {
		try (DwarfExporter exporter = new DwarfExporter(dwarf, program)) {
			exporter.createDebugFromProgram(program, offset);

			GhidraGlobalDecompiler decompiler = new GhidraGlobalDecompiler(program);
			String source = decompiler.dump(exporter.createLineProgram(), offset, dwarf.getName() + ".c");

			try (FileOutputStream sourceOutput = new FileOutputStream(dwarf.getAbsolutePath() + ".c")) {
				sourceOutput.write(source.getBytes(StandardCharsets.UTF_8));
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}

	private TypeNode adaptToTypeNode(Object type, NameMapper mapper, Map<Object, TypeNode> nodes) {

		if (type == null) {
			Logger.error(DwarfExporter.class, "Encountered null type while adapting, assuming void-like!");
			return BaseNode.VOID;
		}

		TypeNode cached = nodes.get(type);

		if (cached != null) {
			return cached;
		}

		switch (type) {
			case TypeDef typedef -> {
				TypeNode node = adaptToTypeNode(typedef.getDataType(), mapper, nodes);

				nodes.put(type, node);
				return node;
			}

			case Array array -> {
				TypeNode element = adaptToTypeNode(array.getDataType(), mapper, nodes);
				ArrayNode node = ArrayNode.of(element, array.getNumElements());

				nodes.put(type, node);
				return node;
			}

			case Structure structure -> {
				String name = structure.getName();

				StructNode node = StructNode.of(mapper.adaptName(name));
				nodes.put(type, node);

				if (name.endsWith(StructNode.INLINE_SUFFIX)) {
					node.markAnonymous();
				}

				for (DataTypeComponent component : structure.getComponents()) {
					DataType underlying = component.getDataType();

					if (underlying instanceof BitFieldDataType field) {
						node.addBitField(field.getBitSize(), component.getFieldName(), component.getComment());
						continue;
					}

					TypeNode child = adaptToTypeNode(underlying, mapper, nodes);
					node.addField(child, component.getFieldName(), component.getComment());
				}

				return node;
			}

			case Union union -> {
				UnionNode node = UnionNode.of(mapper.adaptName(union.getName()));
				nodes.put(type, node);

				for (DataTypeComponent component : union.getComponents()) {
					TypeNode child = adaptToTypeNode(component.getDataType(), mapper, nodes);
					node.addField(child, component.getFieldName(), component.getComment());
				}

				return node;
			}

			case Enum enumeration -> {
				IntegerEnumNode node = IntegerEnumNode.of(mapper.adaptName(enumeration.getName()), BaseNode.of(enumeration.getLength()));
				nodes.put(type, node);

				// this performs a copy and is slow,
				// but for some reason Enum doesn't allow as to access the underlying value map
				long[] values = enumeration.getValues();
				String[] names = enumeration.getNames();

				for (int i = 0; i < values.length; i++) {
					node.addEnumerator(names[i], values[i]);
				}

				return node;
			}

			case FunctionSignature function -> {
				FunctionNode node = FunctionNode.of(null, mapper.adaptName(function.getName()));
				nodes.put(function, node);

				final DataType returnType = function.getReturnType();

				if (returnType != null) {
					node.result = adaptToTypeNode(returnType, mapper, nodes);
				}

				for (ParameterDefinition parameter : function.getArguments()) {
					node.addParameter(parameter.getName(), adaptToTypeNode(parameter.getDataType(), mapper, nodes));
				}

				return node;
			}

			case Pointer pointer -> {
				PointerNode node = PointerNode.of(BaseNode.VOID);
				nodes.put(type, node);

				// specify type only after we already have the pointer
				// so that adaptToTypeNode can't fall into an endless loop
				node.reference = adaptToTypeNode(pointer.getDataType(), mapper, nodes);

				return node;
			}

			case BuiltIn builtin -> {
				BaseNode node = BaseNode.of(builtin.getLength());
				nodes.put(type, node);

				return node;
			}

			case DefaultDataType defaultType -> {
				BaseNode node = BaseNode.of(defaultType.getLength());
				nodes.put(type, node);

				return node;
			}

			default -> throw new RuntimeException("Unhandled class '" + type.getClass().getSimpleName() + "' for type '" + type + "'!");
		}
	}

	public void createDebugFromProgram(Program program, long offset) {

		final Function<Object, TypeNode> converter = getTypeConverter();

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
		 * not yet seen before), we exclude dynamic symbols (by setting the flag
		 * to 'false') dynamic symbols are symbols whose definitions do not reside
		 * in the executable being analyzed but in a separate library.
		 */

		SymbolIterator symbols = program.getSymbolTable().getAllSymbols(false);

		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			Address address = symbol.getAddress();

			Data data = program.getListing().getDataAt(address);
			boolean undefined = Objects.isNull(data) || Undefined.isUndefined(data.getDataType());

			if (symbol.isExternal()) {
				Logger.debug(DwarfExporter.class, "Skipping external symbol: " + symbol.getName());
				continue;
			}

			// only save the symbol if it has a sensible type
			if (!undefined) {
				DataType type = data.getDataType();
				TypeNode node = converter.apply(type);

				createVariable(node, symbol.getName(), address.getOffset() + offset);
			}
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

				long start = address.getOffset() + offset;
				long end = start + function.getBody().getNumAddresses();

				// without specifying the range debuggers will ignore this function
				// (start address is not enough for GDB)
				functionNode.setCodeSpan(start, end);
				createType(functionNode);

				// the symbol itself is not required by GDB,
				// but for completes and compatibility be may as well define it as such
				createSymbol(functionNode.name, start, node.size(getAddressWidth()), ElfSymbolFlag.GLOBAL | ElfSymbolFlag.OBJECT, bss);
			}
		}
	}

	private Function<Object, TypeNode> getTypeConverter() {

		final Map<Object, TypeNode> cache = new IdentityHashMap<>(); // converter cache
		final NameMapper mapper = new NameMapper(); // assigns new names when there is a conflict

		return type -> {
			try {
				return adaptToTypeNode(type, mapper, cache);
			} catch (Exception e) {
				Logger.error(DwarfExporter.class, "Unable to adapt type '" + type + "' of java class '" + type.getClass().getSimpleName() + "'. During conversion exception was thrown: " + e);
			}

			return null;
		};
	}

	private static class NameMapper {

		private final Map<String, Mutable<Integer>> mapping = new HashMap<>();

		public String adaptName(String current) {
			return mapping.computeIfAbsent(current, key -> Mutable.wrap(0)).map(i -> i + 1).to(i -> i == 1 ? current : current + "_" + i);
		}

	}

}
