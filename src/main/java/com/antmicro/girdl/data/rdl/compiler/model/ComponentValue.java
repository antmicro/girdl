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
package com.antmicro.girdl.data.rdl.compiler.model;

import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.util.MathHelper;

import java.util.Optional;

public class ComponentValue extends CompositeValue<ComponentType> {

	public static final long STRIDE_PACKED = 0;

	public long size = 0;
	public long at = 0;
	public long stride = STRIDE_PACKED;
	public long align = 1;
	public long count = 1;

	public ComponentValue(ComponentType type) {
		super(type);
	}

	public long getStart() {
		return MathHelper.alignUp(at, align);
	}

	public long getEnd() {
		return getStart() + getOuterSize();
	}

	public long getStride() {
		return stride == STRIDE_PACKED ? size : stride;
	}

	/**
	 * This is terribly inefficient, but it's also the simples way to do it
	 * this will be invoked each time new child get added.
	 */
	public void updateDimensions() {

		// registers can have the size be explicitly defined using a property
		if (type.kind == ComponentKind.REGISTER) {

			// According to SystemRDL 2.0 specification (10.1.e)
			// The default size of a register, when regwidth is not set or inherited, is 32 bits
			size = Optional.ofNullable(values.get("regwidth")).map(value -> {
				long width = value.toLong();

				// All registers shall have a width = 2^N, where N >= 3.
				// See SystemRDL 2.0 specification (10.1.f)
				if (!MathHelper.isPowerOfTwo(width) || width < 8) {
					ParseError.create(value.location).setUnexpected("'regwidth' of " + value.toLong()).setExpected("a power of 2 greater or equal 8").raise();
				}

				return value.toLong();
			}).orElse(32L);
			return;
		}

		long high = 0;

		for (Value value : values.values()) {
			if (value instanceof ComponentValue component) {
				component.updateDimensions();
				long end = component.getEnd();

				if (end > high) {
					high = end;
				}
			}
		}

		this.size = high;
	}

	/**
	 * Size of the whole component,
	 * including element count (if it is an array).
	 */
	public long getOuterSize() {
		return getStride() * count;
	}

}
