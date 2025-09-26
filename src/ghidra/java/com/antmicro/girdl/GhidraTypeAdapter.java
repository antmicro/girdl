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
import com.antmicro.girdl.model.type.BitsNode;
import com.antmicro.girdl.model.type.IntegerEnumNode;
import com.antmicro.girdl.model.type.PointerNode;
import com.antmicro.girdl.model.type.StructNode;
import com.antmicro.girdl.model.type.TypedefNode;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.Msg;
import ghidra.util.UniversalIdGenerator;

public class GhidraTypeAdapter implements Adapter<DataType> {

	public static final GhidraTypeAdapter INSTANCE = new GhidraTypeAdapter();

	private GhidraTypeAdapter() {
		UniversalIdGenerator.initialize(); // We need to call this before we can use Ghidra types in tests
	}

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
	public DataType adaptBits(BitsNode type) {
		DataType underlying = type.underlying.adapt(this);

		if (!type.fields.isEmpty()) {
			try {
				StructureDataType struct = new StructureDataType("bitfield" + type.fields.size(), 0);
				struct.setPackingEnabled(true);

				for (BitsNode.Entry field : type.fields) {
					struct.addBitField(underlying, field.bits, field.name, field.description);
				}

				return struct;
			} catch (Exception e) {
				Msg.error(this, e);
			}
		}

		return underlying;
	}

	@Override
	public DataType adaptStruct(StructNode element) {
		StructureDataType type = new StructureDataType(element.name, 0);

		for (StructNode.Entry field : element.fields) {
			type.add(field.type.adapt(this), field.name, field.description);
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

}
