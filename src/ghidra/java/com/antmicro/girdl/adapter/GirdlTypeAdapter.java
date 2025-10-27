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
package com.antmicro.girdl.adapter;

import com.antmicro.girdl.data.elf.Storage;
import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypeNode;
import com.antmicro.girdl.model.type.UnionNode;
import com.antmicro.girdl.util.DwarfExporter;
import com.antmicro.girdl.util.Mutable;
import com.antmicro.girdl.util.log.Logger;
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
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.FunctionSignature;

import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.function.Function;

public class GirdlTypeAdapter {

	final Map<Object, TypeNode> nodes = new IdentityHashMap<>(); // converter cache
	final NameMapper mapper = new NameMapper(); // assigns new names when there is a conflict

	private TypeNode adaptToTypeNode(Object type) {

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
				TypeNode node = adaptToTypeNode(typedef.getDataType());

				nodes.put(type, node);
				return node;
			}

			case Array array -> {
				TypeNode element = adaptToTypeNode(array.getDataType());
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

					TypeNode child = adaptToTypeNode(underlying);
					node.addField(child, component.getFieldName(), component.getComment());
				}

				return node;
			}

			case Union union -> {
				UnionNode node = UnionNode.of(mapper.adaptName(union.getName()));
				nodes.put(type, node);

				for (DataTypeComponent component : union.getComponents()) {
					TypeNode child = adaptToTypeNode(component.getDataType());
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
					node.result = adaptToTypeNode(returnType);
				}

				for (ParameterDefinition parameter : function.getArguments()) {
					TypeNode varType = adaptToTypeNode(parameter.getDataType());
					node.addParameter(parameter.getName(), varType, Storage.UNKNOWN);
				}

				return node;
			}

			case Pointer pointer -> {
				PointerNode node = PointerNode.of(BaseNode.VOID);
				nodes.put(type, node);

				// specify type only after we already have the pointer
				// so that adaptToTypeNode can't fall into an endless loop
				node.reference = adaptToTypeNode(pointer.getDataType());

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

	public Function<Object, TypeNode> getTypeConverter() {
		return type -> {
			try {
				return adaptToTypeNode(type);
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
