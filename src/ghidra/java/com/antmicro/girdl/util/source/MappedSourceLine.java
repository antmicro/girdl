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
package com.antmicro.girdl.util.source;

public final class MappedSourceLine extends SourceLine {

	public final long line;
	public final long address;

	MappedSourceLine(long line, String source, long address) {
		super(source);

		this.line = line;
		this.address = address;
	}

	@Override
	public String toString() {
		return "0x" + Long.toHexString(address) + ": " + getSourceLine();
	}

	@Override
	public int compareTo(SourceLine other) {
		if (other instanceof MappedSourceLine mapped) {
			return Long.compare(address, mapped.address);
		}

		return super.compareTo(other);
	}

}
