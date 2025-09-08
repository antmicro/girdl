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
package com.antmicro.girdl.data;

import com.antmicro.girdl.util.RecursiveTaskMonitor;
import com.antmicro.girdl.util.file.Resource;

import java.util.stream.Stream;

public final class DirectoryImporter implements Importer {

	public static final FilePredicate PREDICATE = new FilePredicate(Resource::isDirectory, DirectoryImporter::new, "directory");

	final Resource[] files;

	public DirectoryImporter(Resource directory) {
		this(directory.list());
	}

	public DirectoryImporter(Resource[] files) {
		this.files = files;
	}

	@Override
	public void load(Context context, RecursiveTaskMonitor monitor) {
		monitor.addWork(files.length);

		Stream.of(files).map(Importer::of).forEach(importer -> {
			importer.load(context, monitor);
			monitor.done();
		});
	}

}
