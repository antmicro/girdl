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

import com.antmicro.girdl.util.MathHelper;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class SegmentedBuffer extends DataWriter {

	private String name;
	private int alignment = 1;
	private ContentPolicy policy = ContentPolicy.MIXED;
	private final List<DataWriter> blocks = new ArrayList<>();
	private final ByteOrder order;

	/**
	 * @param parent Optional, use null for the root buffer.
	 */
	SegmentedBuffer(SegmentedBuffer parent, ByteOrder order) {
		super(parent);
		this.order = order;
	}

	private ResizableBuffer getBufferBlock() {
		if (blocks.isEmpty() || !(blocks.getLast() instanceof ResizableBuffer)) {
			ResizableBuffer buffer = new ResizableBuffer(this, order);
			buffer.assertContentPolicy(policy);
			blocks.add(buffer);
		}

		return (ResizableBuffer) blocks.getLast();
	}

	@Override
	byte[] toBytes(int start) {
		final int padding = (int) MathHelper.getPadding(start, alignment);

		if (blocks.isEmpty()) {
			return new byte[padding];
		}

		int size = 0;
		List<byte[]> parts = new ArrayList<>(blocks.size() + (padding > 0 ? 1 : 0));

		if (padding > 0) {
			parts.add(new byte[padding]);
		}

		for (DataWriter block : blocks) {
			byte[] part = block.toBytes(size + start);
			size += part.length;
			parts.add(part);
		}

		// if there is only one child skip memory allocation
		if (parts.size() == 1) {
			return parts.getFirst();
		}

		int offset = 0;
		byte[] merged = new byte[size + padding];

		for (byte[] part : parts) {
			System.arraycopy(part, 0, merged, offset, part.length);
			offset += part.length;
		}

		return merged;
	}

	@Override
	void assertContentPolicy(ContentPolicy policy) {
		if (policy == ContentPolicy.DATA) {
			throw new RuntimeException("Content policy violation, can't create SegmentedBuffer in DATA only SegmentedBuffer!");
		}
	}

	@Override
	public List<DataWriter> children() {
		return blocks;
	}

	@Override
	public SegmentedBuffer putByte(int value) {
		getBufferBlock().putByte(value);
		return this;
	}

	@Override
	public SegmentedBuffer putString(String value) {
		getBufferBlock().putString(value);
		return this;
	}

	@Override
	public SegmentedBuffer putBytes(byte... value) {
		getBufferBlock().putBytes(value);
		return this;
	}

	@Override
	public SegmentedBuffer putShort(int value) {
		getBufferBlock().putShort(value);
		return this;
	}

	@Override
	public SegmentedBuffer putInt(int value) {
		getBufferBlock().putInt(value);
		return this;
	}

	@Override
	public SegmentedBuffer putLong(long value) {
		getBufferBlock().putLong(value);
		return this;
	}

	@Override
	public SegmentedBuffer putFloat(float value) {
		getBufferBlock().putFloat(value);
		return this;
	}

	@Override
	public int size() {
		int bytes = 0;

		for (DataWriter writer : blocks) {
			bytes += writer.size();
		}

		return bytes;
	}

	@Override
	public int offset() {
		return Math.toIntExact(MathHelper.alignUp(super.offset(), alignment));
	}

	@Override
	public int outerSize(int offset) {
		return Math.toIntExact(MathHelper.getPadding(offset, alignment) + size());
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder("Group ");

		if (name != null && !name.isEmpty()) {
			builder.append("'").append(name).append("', ");
		}

		if (policy != ContentPolicy.MIXED) {
			builder.append(policy).append(" only, ");
		}

		builder.append("align=").append(alignment).append(", ");
		builder.append(order);

		return builder.toString();
	}

	public SegmentedBuffer erase() {
		blocks.clear();
		return this;
	}

	public SegmentedBuffer putSegment(ByteOrder order) {
		SegmentedBuffer segmented = new SegmentedBuffer(this, order);
		segmented.assertContentPolicy(policy);
		blocks.add(segmented);
		return segmented;
	}

	public SegmentedBuffer setName(String name) {
		this.name = name;
		return this;
	}

	public SegmentedBuffer setPolicy(ContentPolicy policy) {
		this.policy = policy;
		return this;
	}

	public SegmentedBuffer setAlignment(int alignment) {
		this.alignment = alignment;
		return this;
	}

	public SegmentedBuffer putSegment() {
		return putSegment(order);
	}

	@Override
	public SegmentedBuffer putLink(int bytes, Consumer<ByteBuffer> linker) {
		getBufferBlock().putLink(bytes, linker);
		return this;
	}

}
