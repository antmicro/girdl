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
package com.antmicro.girdl.data.elf.source;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public final class SourceFactory {

	private final List<SourceLine> lines = new ArrayList<>();

	private long nextLine() {
		return lines.size() + 1;
	}

	/**
	 * Adds a new mapped line, mapped lines contain an address that can be used to
	 * store them in a DWARF Line Number Program, using the {@link com.antmicro.girdl.data.elf.LineProgrammer}.
	 *
	 * @param source single line of text
	 * @param address address of the first instruction of that line
	 */
	public void addLine(String source, long address) {
		lines.add(new MappedSourceLine(nextLine(), source, address));
	}

	/**
	 * Adds a new unmapped line, unmapped lines contain no address, their text still
	 * contributes to the final code, but they are not stored in the DWARF Line Number Program.
	 *
	 * @param source single line of text
	 */
	public void addLine(String source) {
		lines.add(new UnmappedSourceLine(source));
	}

	/**
	 * Adds an empty unnamed line,
	 * can be used to add spacing.
	 */
	public void addEmpty() {
		addLine("");
	}

	/**
	 * Export all the lines into a single source document,
	 * both mapped and unmapped ones.
	 */
	public String asSource() {
		return lines.stream().map(SourceLine::getSourceLine).collect(Collectors.joining("\n"));
	}

	/**
	 * Export all the lines into a single source document,
	 * both mapped and unmapped ones.
	 */
	public void saveSource(String path) {
		String source = asSource();

		try (FileOutputStream sourceOutput = new FileOutputStream(path)) {
			sourceOutput.write(source.getBytes(StandardCharsets.UTF_8));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Feed all the mapped lines into the given consumer,
	 * can be used to store the mapping in DWARF using {@link com.antmicro.girdl.data.elf.LineProgrammer}.
	 */
	public void forEachMapped(Consumer<MappedSourceLine> consumer) {
		lines.stream().filter(line -> line instanceof MappedSourceLine).sorted().map(line -> (MappedSourceLine) line).forEach(consumer);
	}

}
