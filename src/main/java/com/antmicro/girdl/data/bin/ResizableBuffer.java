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
package com.antmicro.girdl.data.bin;

import com.google.common.io.LittleEndianDataOutputStream;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class ResizableBuffer extends DataWriter {

	private final ByteArrayOutputStream stream = new ByteArrayOutputStream();
	private final DataOutput writer;
	private final ByteOrder order;

	private List<Link> linkers = null;

	/**
	 * @param parent Optional, use null for the root buffer.
	 * @param order Endianness of the data.
	 */
	public ResizableBuffer(DataWriter parent, ByteOrder order) {
		super(parent);
		this.writer = order == ByteOrder.LITTLE_ENDIAN ? new LittleEndianDataOutputStream(stream) : new DataOutputStream(stream);
		this.order = order;
	}

	@Override
	byte[] toBytes(int offset) {
		byte[] bytes = stream.toByteArray();

		if (linkers != null) {
			for (Link linker : linkers) {
				linker.link(bytes);
			}
		}

		return bytes;
	}

	@Override
	public List<DataWriter> children() {
		return List.of();
	}

	@Override
	void assertContentPolicy(ContentPolicy policy) {
		if (policy == ContentPolicy.SEGMENTS) {
			throw new RuntimeException("Content policy violation, can't create ResizableBuffer in SEGMENTS only SegmentedBuffer!");
		}
	}

	@Override
	public ResizableBuffer putByte(int value) {
		try {
			writer.writeByte(value);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ResizableBuffer putString(String value) {
		try {
			writer.writeBytes(value);
			writer.writeByte(0);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ResizableBuffer putBytes(byte[] value) {
		try {
			writer.write(value);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ResizableBuffer putShort(int value) {
		try {
			writer.writeShort(value);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ResizableBuffer putInt(int value) {
		try {
			writer.writeInt(value);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ResizableBuffer putLong(long value) {
		try {
			writer.writeLong(value);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public ResizableBuffer putFloat(float value) {
		try {
			writer.writeFloat(value);
			return this;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public int size() {
		return stream.size();
	}

	@Override
	public int outerSize(int offset) {
		return size();
	}

	@Override
	public ResizableBuffer putLink(int bytes, Consumer<ByteBuffer> linker) {
		if (linkers == null) {
			linkers = new ArrayList<>();
		}

		// size is equal to the current position
		final int offset = size();

		putSpace(bytes, 0);
		linkers.add(new Link(offset, bytes, linker));
		return this;
	}

	@Override
	public String toString() {
		return "Buffer " + size() + " bytes, " + (linkers == null ? 0 : linkers.size()) + " links, " + order;
	}

	private class Link {
		final int offset;
		final int bytes;
		final Consumer<ByteBuffer> linker;

		void link(byte[] buffer) {
			linker.accept(ByteBuffer.wrap(buffer, offset, bytes).order(order));
		}

		private Link(int offset, int bytes, Consumer<ByteBuffer> linker) {
			this.offset = offset;
			this.bytes = bytes;
			this.linker = linker;
		}
	}

}
