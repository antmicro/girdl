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

import com.antmicro.girdl.model.Binding;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.util.file.Resource;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.Msg;

public final class JsonBindingImporter extends JsonImporter {

	public static final FilePredicate PREDICATE = FilePredicate.byExtension(JsonBindingImporter::new, ".json");

	private static final String HEADER_NAME = "Peripheral Map 1.0";

	JsonBindingImporter(Resource file) {
		super(file);
	}

	@Override
	protected boolean accept(JsonElement json) {
		if (!json.isJsonObject()) {
			return false;
		}

		JsonElement header = json.getAsJsonObject().get("Header");

		if (header == null || header.isJsonNull()) {
			return false;
		}

		return HEADER_NAME.equals(header.getAsString());
	}

	@Override
	protected void parse(JsonElement json, Context context) {
		parseNode(json.getAsJsonObject().get("Root"), context);
	}

	private void parseNode(JsonElement node, Context context) {

		// null children should just be ignored, this allows for the creation of an empty file
		if (node.isJsonNull()) {
			return;
		}

		JsonObject self = node.getAsJsonObject();

		// for now, we ignore the tree structure of the data and treat it as independent elements
		for (JsonElement entry : self.getAsJsonArray("Children")) {
			parseNode(entry.getAsJsonObject(), context);
		}

		// append each peripheral-binding pair
		for (JsonElement bind : self.getAsJsonArray("Bindings")) {
			parseBindPoint(self, bind.getAsJsonObject(), context);
		}
	}

	private void parseBindPoint(JsonObject node, JsonObject bind, Context context) {

		final String name = node.get("Name").getAsString();
		final JsonElement element = node.get("Alias");

		final String alias = (element == null || element.isJsonNull()) ? name : element.getAsString();
		final Peripheral peripheral = context.createPeripheral(name);

		if ("Bus".equals(bind.get("Type").getAsString())) {
			long address = bind.get("Value").getAsLong();

			Binding binding = peripheral.createBinding(alias, address);
			Msg.trace(this, "Created binding of " + binding);
		}
	}

}
