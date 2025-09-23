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
package com.antmicro.girdl.util;

import com.antmicro.girdl.util.file.Resource;
import ghidra.formats.gfilesystem.FileSystemProbeConflictResolver;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileImpl;
import ghidra.util.task.TaskMonitor;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public final class GhidraFile extends Resource {

	private final GFile file;

	GhidraFile(GFile file) {
		this.file = file;
	}

	/**
	 * Create a resource backed by a Ghidra File,
	 * silently returns null if given a null value.
	 */
	public static Resource fromGhidraFile(GFile file) {
		return file == null ? null : new GhidraFile(file);
	}

	/**
	 * Create a resource backed by a Ghidra File,
	 * silently returns null if given a null value.
	 */
	public static Resource fromJavaFile(File file) {
		if (file == null) {
			return null;
		}

		FileSystemService fss = FileSystemService.getInstance();

		return fromGhidraFile(GFileImpl.fromFSRL(
				fss.getLocalFS(),
				fss.getLocalFS().getRootDir(),
				fss.getLocalFSRL(file),
				file.isDirectory(),
				-1
		));
	}

	@Override
	public Resource[] list() {
		try {
			return file.getListing().stream().map(GhidraFile::new).toArray(Resource[]::new);
		} catch (Exception e) {
			throw new RuntimeException("Failed to list entries of '" + this + "'", e);
		}
	}

	@Override
	public Resource then(String string) {
		try {
			return file.getListing().stream().filter(file -> file.getName().equals(string)).map(GhidraFile::new).findAny().orElseThrow();
		} catch (IOException e) {
			throw new RuntimeException("No entry '" + string + "' found in '" + this + "'", e);
		}
	}

	@Override
	public Resource stepInto() {
		FileSystemService fss = FileSystemService.getInstance();

		try {
			FileSystemRef ref = fss.probeFileForFilesystem(file.getFSRL(), TaskMonitor.DUMMY, FileSystemProbeConflictResolver.CHOOSEFIRST);
			Resource file = new GhidraFile(ref.getFilesystem().getRootDir());
			ref.close();

			return file;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public InputStream getInputStream() {
		try {
			return file.getFilesystem().getInputStream(file, TaskMonitor.DUMMY);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public BufferedReader getBufferedReader() {
		return new BufferedReader(new InputStreamReader(getInputStream()));
	}

	@Override
	public String toString() {
		return file.getFSRL().toPrettyString();
	}

	@Override
	public String getName() {
		return file.getName();
	}

	@Override
	public boolean isFile() {
		return !file.isDirectory();
	}

	@Override
	public boolean isDirectory() {
		return file.isDirectory();
	}

	@Override
	public boolean exists() {
		return true;
	}

	@Override
	public Resource back() {
		return new GhidraFile(file.getParentFile());
	}

	public static void register() {
		Resource.setGhidraFileConverter(file -> fromJavaFile(file.toFile()));
	}

}
