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

import com.antmicro.girdl.model.type.Adapter;
import com.antmicro.girdl.model.type.ArrayNode;
import com.antmicro.girdl.model.type.BaseNode;
import com.antmicro.girdl.model.type.FunctionNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypedefNode;
import com.antmicro.girdl.model.type.UnionNode;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.util.Msg;

public class GhidraTypeAdapter implements Adapter<DataType> {

	public static final GhidraTypeAdapter INSTANCE = new GhidraTypeAdapter();

	@Override
	public DataType adaptArray(ArrayNode type) {
		return new ArrayDataType(type.element.adapt(this), type.length);
	}

	@Override
	public DataType adaptBase(BaseNode type) {

		final int bytes = type.bytes;

		// try to assign some sensible data type
		if (bytes == 8) return StructConverter.QWORD;
		if (bytes == 4) return StructConverter.DWORD;
		if (bytes == 2) return StructConverter.WORD;
		if (bytes == 1) return StructConverter.BYTE;

		// otherwise use whatever fits
		return new ArrayDataType(StructConverter.BYTE, bytes);
	}

	@Override
	public DataType adaptStruct(StructNode element) {
		StructureDataType type = new StructureDataType(element.name + (element.isAnonymous() ? StructNode.INLINE_SUFFIX : ""), 0);

		try {
			for (StructNode.Entry field : element.fields) {

				if (field.isBitField()) {
					type.addBitField(field.type.adapt(this), field.bits, field.name, field.description);
					continue;
				}

				type.add(field.type.adapt(this), field.name, field.description);
			}
		} catch (Exception e) {
			Msg.error(this, e);
		}

		return type;
	}

	@Override
	public DataType adaptTypedef(TypedefNode type) {
		return new TypedefDataType(type.name, type.adapt(this));
	}

	@Override
	public DataType adaptPointer(PointerNode type) {
		return new PointerDataType(type.reference.adapt(this));
	}

	@Override
	public DataType adaptEnum(IntegerEnumNode type) {
		EnumDataType enumeration = new EnumDataType(type.name, type.underlying.adapt(this).getLength());

		for (IntegerEnumNode.Enumerator enumerator : type.enumerators) {
			enumeration.add(enumerator.name, enumerator.value);
		}

		return enumeration;
	}

	@Override
	public DataType adaptFunction(FunctionNode type) {
		FunctionDefinitionDataType function = new FunctionDefinitionDataType(type.name);
		function.setNoReturn(type.hasNoReturn());

		if (!type.hasNoReturn()) {
			function.setReturnType(type.result.adapt(this));
		}

		ParameterDefinition[] params = new ParameterDefinition[type.parameters.size()];

		for (int i = 0; i < params.length; i ++) {
			FunctionNode.Variable parameter = type.parameters.get(i);

			params[i] = new ParameterDefinitionImpl(parameter.name, parameter.type.adapt(this), "");
		}

		function.setArguments(params);
		return function;
	}

	@Override
	public DataType adaptUnion(UnionNode type) {
		UnionDataType union = new UnionDataType(type.name);

		for (UnionNode.Entry field : type.fields) {
			union.add(field.type.adapt(this), field.name, field.description);
		}

		return union;
	}

}
