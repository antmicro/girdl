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

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

/**
 * SegmentedFile allows for creating binary data files in a non-linear fashion,
 * the file consists of a single so-called "segment" (the root segment, accessible via
 * {@link #getRootBuffer()}) this buffer (a {@link DataWriter}) can contain data and
 * other buffers,  creating a tree structure. All nodes in that tree can be written to in any order.
 * <p>
 * Once {@link #close()} is called the tree is flattened, and the embedded links (lambdas) resolved,
 * those lambdas are free to modify the data, but can't change the overall length.
 */
public class SegmentedFile implements AutoCloseable {

	private final Map<String, SegmentedBuffer> named = new HashMap<>();

	private final OutputStream output;
	private final SegmentedBuffer buffer;

	public SegmentedFile(File file, ByteOrder order) {
		try {
			this.output = new FileOutputStream(file, false);
			this.buffer = new SegmentedBuffer(null, order);
		} catch (Exception e) {
			throw new RuntimeException("Can't open file '" + file + "'", e);
		}
	}

	@Override
	public void close() {
		try {
			this.output.write(buffer.toBytes(0));
			this.output.flush();
			this.output.close();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public SegmentedBuffer getRootBuffer() {
		return buffer;
	}

}
