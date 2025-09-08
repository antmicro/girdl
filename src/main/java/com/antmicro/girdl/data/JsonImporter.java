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
import com.google.gson.JsonElement;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;

public abstract class JsonImporter implements Importer {

	final JsonReader reader;
	final String name;

	JsonImporter(Resource file) {
		this.reader = new JsonReader(file.getBufferedReader());
		this.reader.setLenient(true);
		this.name = file.getName();
	}

	@Override
	public void load(Context context, RecursiveTaskMonitor monitor) {
		JsonElement element = Streams.parse(reader);

		if (accept(element)) {
			parse(element, context);
		}
	}

	boolean accept(JsonElement json) {
		return true;
	}

	protected abstract void parse(JsonElement element, Context context);

}
