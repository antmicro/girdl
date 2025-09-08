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
import ghidra.util.Msg;

public interface Importer {

	FilePredicate.Combined ALL = FilePredicate.combined(
			DirectoryImporter.PREDICATE,
			ArchiveImporter.PREDICATE,
			SvdImporter.PREDICATE,
			RdlImporter.PREDICATE,
			JsonRegisterImporter.PREDICATE,
			DummyImporter.JSON_IGNORABLE,
			JsonBindingImporter.PREDICATE
	);

	void load(Context context, RecursiveTaskMonitor monitor);

	default void load(Context context) {
		load(context, RecursiveTaskMonitor.DUMMY);
	}

	static Importer of(Resource file) {
		if (file == null) {
			return DummyImporter.INSTANCE;
		}

		try {
			return ALL.getMatching(file).orElseThrow().get(file);
		} catch (Exception e) {
			Msg.error(file, e);

			return DummyImporter.createVerbose(file);
		}
	}

	static Importer of(Resource... files) {
		return new DirectoryImporter(files);
	}

}
