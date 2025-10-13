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

import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;

/**
 * A single node in the {@link SegmentedFile} buffer tree. Data buffers can be used
 * to write linear binary data, append links, and other buffers. All data will be written in
 * order it was appended to the buffer.
 */
public abstract sealed class DataWriter permits ResizableBuffer, SegmentedBuffer {

	protected final DataWriter parent;

	/**
	 * @param parent Optional, use null for the root buffer.
	 */
	protected DataWriter(DataWriter parent) {
		this.parent = parent;
	}

	abstract byte[] toBytes(int offset);
	abstract void assertContentPolicy(ContentPolicy policy);

	/**
	 * Offset (start of in relation to the start of this buffer), in bytes, of the
	 * given buffer, this value will change as data is being appended between the
	 * start of the parent and start of the child buffer.
	 *
	 * @param child Buffer, must be a direct child of this buffer.
	 * @return Offset in bytes.
	 */
	public final int offsetOf(DataWriter child) {
		int address = offset();

		for (DataWriter writer : children()) {
			if (writer == child) {
				return address;
			}

			address += writer.outerSize(address);
		}

		throw new RuntimeException("Unable to find offset of unrelated buffer!");
	}

	/**
	 * Get the index of the given buffer in the list of children of this buffer,
	 * this value can't change.
	 *
	 * @param child Buffer, must be a direct child of this buffer.
	 * @return Zero-based index in the child list.
	 */
	public final int indexOf(DataWriter child) {
		List<DataWriter> blocks = children();

		for (int i = 0; i < blocks.size(); i ++) {
			if (blocks.get(i) == child) {
				return i;
			}
		}

		throw new RuntimeException("Unable to find index of unrelated buffer!");
	}

	/**
	 * Offset, in bytes, of this buffer in relation to the start of the file,
	 * this value will change as data is being appended between the
	 * start of the file and start of the child buffer.
	 *
	 * @return Offset in bytes.
	 */
	public int offset() {
		return parent == null ? 0 : parent.offsetOf(this);
	}

	/**
	 * Fill the buffer with the given byte, until a specific length is reached. If
	 * the buffer is already of that length or longer not bytes will be appended.
	 *
	 * @param bytes Number of bytes to ensure.
	 * @param value Byte value to use.
	 */
	public final void fillUpToWith(int bytes, int value) {
		int padding = bytes - size();

		if (padding > 0) {
			putSpace(padding, value);
		}
	}

	/**
	 * Based on <a href="https://android.googlesource.com/platform/libcore/+/522b917/dex/src/main/java/com/android/dex/Leb128.java">Google's Implementation</a>.
	 */
	public final DataWriter putSignedLeb128(int value) {
		int remaining = value >> 7;
		boolean hasNext = true;
		int end = ((value & Integer.MIN_VALUE) == 0) ? 0 : -1;

		while (hasNext) {
			hasNext = (remaining != end) || ((remaining & 1) != ((value >> 6) & 1));

			putByte((value & 0x7f) | (hasNext ? 0x80 : 0));
			value = remaining;
			remaining >>= 7;
		}

		return this;
	}

	/**
	 * Based on <a href="https://android.googlesource.com/platform/libcore/+/522b917/dex/src/main/java/com/android/dex/Leb128.java">Google's Implementation</a>.
	 */
	public final DataWriter putUnsignedLeb128(int value) {
		int remaining = value >>> 7;

		while (remaining != 0) {
			putByte((value & 0x7f) | 0x80);
			value = remaining;
			remaining >>>= 7;
		}

		putByte(value & 0x7f);
		return this;
	}

	public final DataWriter putBool(boolean flag) {
		putByte(flag ? 1 : 0);
		return this;
	}

	public final DataWriter putSpace(int bytes, int value) {
		for (int i = 0; i < bytes; i ++) {
			putByte(value);
		}

		return this;
	}

	public final DataWriter putBytes(int... value) {
		for (int v : value) {
			putByte(v);
		}
		return this;
	}

	public abstract DataWriter putByte(int value);
	public abstract DataWriter putString(String value);
	public abstract DataWriter putBytes(byte... value);
	public abstract DataWriter putShort(int value);
	public abstract DataWriter putInt(int value);
	public abstract DataWriter putLong(long value);
	public abstract DataWriter putFloat(float value);
	public abstract DataWriter putLink(int bytes, Consumer<ByteBuffer> linker);

	/**
	 * Size of this buffer's content, including all descendants, in bytes.
	 * This value will change as data is being appended to this and descendant buffers.
	 *
	 * @return Size in bytes.
	 */
	public abstract int size();

	/**
	 *  Size of this buffer (including padding required by the alignment constraints), including all descendants, in bytes.
	 *  his value will change as data is being appended to this and descendant buffers, as well as, when the buffer
	 *  offset in relation to the start of the file (requiring changes to padding) changes.
	 *
	 *  @return Size in bytes, including padding.
	 */
	public abstract int outerSize(int offset);

	/**
	 * Get the list of sub-buffers that belong directly to this buffer,
	 * The returned list must not be modified.
	 *
	 * @return List of child buffers.
	 */
	public abstract List<DataWriter> children();

	/**
	 * Insert a link-time resolved byte into the buffer,
	 * this is a helper for {@link #putLink(int, Consumer)}.
	 *
	 * @param value Supplier for a value to be resolved at link time
	 */
	public final DataWriter putByte(IntSupplier value) {
		putLink(1, buffer -> buffer.put((byte) value.getAsInt()));
		return this;
	}

	/**
	 * Insert a link-time resolved short (2 bytes) into the buffer,
	 * this is a helper for {@link #putLink(int, Consumer)}.
	 *
	 * @param value Supplier for a value to be resolved at link time
	 */
	public final DataWriter putShort(IntSupplier value) {
		putLink(2, buffer -> buffer.putShort((short) value.getAsInt()));
		return this;
	}

	/**
	 * Insert a link-time resolved integer (4 bytes) into the buffer,
	 * this is a helper for {@link #putLink(int, Consumer)}.
	 *
	 * @param value Supplier for a value to be resolved at link time
	 */
	public final DataWriter putInt(IntSupplier value) {
		putLink(4, buffer -> buffer.putInt(value.getAsInt()));
		return this;
	}

	/**
	 * Insert a link-time resolved long (8 bytes) into the buffer,
	 * this is a helper for {@link #putLink(int, Consumer)}.
	 *
	 * @param value Supplier for a value to be resolved at link time
	 */
	public final DataWriter putLong(LongSupplier value) {
		putLink(8, buffer -> buffer.putLong(value.getAsLong()));
		return this;
	}

	/**
	 * Write an integer of width specified using the bits parameter,
	 * supported values include 8, 16, 32, 64.
	 *
	 * @param bits Number of bts to use
	 * @param value Value to write
	 */
	public final DataWriter putDynamic(int bits, long value) {
		if (bits == 8) return putByte((int) value);
		if (bits == 16) return putShort((int) value);
		if (bits == 32) return putInt((int) value);
		if (bits == 64) return putLong(value);

		throw new RuntimeException("Unsupported bit width of " + value + "!");
	}

}
