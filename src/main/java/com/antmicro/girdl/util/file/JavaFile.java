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
package com.antmicro.girdl.util.file;

import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFileImpl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

final class JavaFile extends Resource {

	private final File file;

	JavaFile(File file) {
		this.file = file;
	}

	@Override
	public Resource[] list() {
		try {
			return Arrays.stream(Objects.requireNonNull(file.listFiles())).map(JavaFile::new).toArray(Resource[]::new);
		} catch (Exception e) {
			throw new RuntimeException("Failed to list entries of '" + this + "'", e);
		}
	}

	@Override
	public Resource then(String string) {
		return new JavaFile(file.toPath().resolve(string).toFile());
	}

	@Override
	public Resource stepInto() {
		return toGhidraFile().stepInto();
	}

	@Override
	public InputStream getInputStream() {
		try {
			return new FileInputStream(file);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public BufferedReader getBufferedReader() {
		try {
			return new BufferedReader(new FileReader(file));
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString() {
		return "file:/" + file.getPath();
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public boolean isFile() {
		return file.isFile();
	}

	@Override
	public boolean isDirectory() {
		return file.isDirectory();
	}

	@Override
	public boolean exists() {
		return file.exists();
	}

	@Override
	public Resource back() {
		return new JavaFile(new File(file.getParent()));
	}

	private Resource toGhidraFile() {
		FileSystemService fss = FileSystemService.getInstance();

		return Resource.fromGhidraFile(GFileImpl.fromFSRL(
				fss.getLocalFS(),
				fss.getLocalFS().getRootDir(),
				fss.getLocalFSRL(file),
				isDirectory(),
				-1
		));
	}

}
