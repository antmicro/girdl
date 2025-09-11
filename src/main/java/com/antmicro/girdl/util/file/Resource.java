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

import ghidra.formats.gfilesystem.GFile;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;

public sealed abstract class Resource permits GhidraFile, JavaFile {

	/**
	 * Create a resource backed by a Java File,
	 * silently returns null if given a null value.
	 */
	public static Resource fromJavaFile(File file) {
		return file == null ? null : new JavaFile(file);
	}

	/**
	 * Create a resource backed by a Ghidra File,
	 * silently returns null if given a null value.
	 */
	public static Resource fromGhidraFile(GFile file) {
		return file == null ? null : new GhidraFile(file);
	}

	/**
	 * Create a resource from a string path,
	 * silently returns null if given a null value.
	 */
	public static Resource fromLocalPath(String path) {
		return path == null ? null : fromJavaFile(new File(path));
	}

	/**
	 * Create a resource from a string universal path (path with protocol),
	 * silently returns null if given a null value.
	 */
	public static Resource fromUniversalPath(String path) {
		return path == null ? null : (isRemote(path) ? RemoteCache.fetch(path) : fromLocalPath(path));
	}

	/**
	 * Create a resource from a Java Resource,
	 * silently returns null if given a null value.
	 */
	public static <T> Resource fromJavaResource(T object, String path) {
		if (path == null) {
			return null;
		}

		URL url = object.getClass().getResource(path);

		if (url == null) {
			throw new RuntimeException("Resource '" + path + "' not found!");
		}

		try {
			return fromJavaFile(Paths.get(url.toURI()).toFile());
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	public abstract Resource[] list();
	public abstract Resource then(String string);
	public abstract Resource stepInto();
	public abstract InputStream getInputStream();
	public abstract BufferedReader getBufferedReader();
	public abstract String getName();
	public abstract boolean isFile();
	public abstract boolean isDirectory();
	public abstract boolean exists();
	public abstract Resource back();

	public Resource find(String path) {
		Resource cwd = this;

		for (String part : path.split("/")) {
			cwd = cwd.then(part);
		}

		return cwd;
	}

	public boolean endsWith(String suffix) {
		return getName().endsWith(suffix);
	}

	private static boolean isRemote(String path) {
		return path.startsWith("https://") || path.startsWith("http://");
	}
}
