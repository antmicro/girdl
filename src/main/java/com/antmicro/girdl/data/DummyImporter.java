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

public final class DummyImporter implements Importer {

	public static final DummyImporter INSTANCE = createVerbose(null);
	public static final FilePredicate JSON_IGNORABLE = FilePredicate.byExtension(DummyImporter::createSilent, "-interruptInfo.json", "-classesInfo.json").withoutDescription();

	private final String path;
	private final boolean warn;

	private DummyImporter(Resource resource, boolean warn) {
		this.path = resource == null ? "(null)" : "'" + resource + "'";
		this.warn = warn;
	}

	@Override
	public void load(Context context, RecursiveTaskMonitor monitor) {
		if (warn) Msg.warn(this, "Dummy importer invoked for path: " + path + "!");
	}

	public static DummyImporter createVerbose(Resource resource) {
		return new DummyImporter(resource, true);
	}

	public static DummyImporter createSilent(Resource resource) {
		return new DummyImporter(resource, false);
	}

}
