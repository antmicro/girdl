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

import com.antmicro.girdl.util.FileHelper;
import com.google.common.base.Stopwatch;
import ghidra.util.Msg;
import org.h2.util.IOUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class RemoteCache {

	private static final RemoteCache INSTANCE = new RemoteCache();
	private final Map<URI, File> cache = new HashMap<>();

	private File fetchRemote(URL url) {

		Stopwatch stopwatch = Stopwatch.createStarted();

		try {
			try (InputStream input = url.openStream()) {
				Msg.info(this, "Cache miss for '" + url + "', fetching from remote server...");

				File file = FileHelper.createTempFile(".tar.gz");
				file.deleteOnExit();

				try (OutputStream output = new FileOutputStream(file)) {
					IOUtils.copy(input, output);
					Msg.info(this, "Completed download of '" + url + "' in " + stopwatch.elapsed(TimeUnit.MILLISECONDS) + "ms");
					output.flush();
				}

				return file;
			}
		} catch (Exception e) {
			return null;
		}
	}

	private Resource getRemoteResource(String path) {
		try {
			Msg.info(this, "Remote resource '" + path + "' requested");
			URL url = new URL(path);
			return Resource.fromJavaFile(cache.computeIfAbsent(url.toURI(), uri -> fetchRemote(url)));
		} catch (Exception e) {
			return null;
		}
	}

	public static Resource fetch(String path) {
		return INSTANCE.getRemoteResource(path);
	}

}
