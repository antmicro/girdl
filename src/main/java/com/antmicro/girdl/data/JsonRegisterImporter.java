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

import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.model.Register;
import com.antmicro.girdl.util.DataSource;
import com.antmicro.girdl.util.file.Resource;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class JsonRegisterImporter extends JsonImporter {

	public static final FilePredicate PREDICATE = FilePredicate.byExtension(JsonRegisterImporter::new, "-registersInfo.json");

	JsonRegisterImporter(Resource file) {
		super(file);
	}

	private String getFileName(String filename) {
		int dot = filename.indexOf('.');
		if (dot == -1) dot = filename.length();

		return filename.substring(0, dot);
	}

	@Override
	protected void parse(JsonElement json, Context context) {

		Peripheral peripheral = new Peripheral(getFileName(name));

		if (json.isJsonArray()) {
			parseArray(json.getAsJsonArray(), peripheral);
		}

		// we don't provide an uniqueFallbackName here as
		// 1. We don't have any available
		// 2. In JSON import if something is duplicated we should probably just ignore or merge it
		Msg.trace(this, "Created peripheral " + peripheral.name);
		context.addPeripheral(peripheral, Optional.empty());
	}

	private void parseArray(JsonArray array, Peripheral peripheral) {

		final List<JsonObject> sets = getValidRegisterSets(array);

		if (sets.size() != 1) {
			Msg.warn(this, "Peripheral " + peripheral.name + " has " + array.size() + " valid register sets");
		}

		if (sets.isEmpty()) {
			return;
		}

		// currently to not cause havoc later we only parse ONE register set
		// in the future we could create a separate peripheral for each set or do something even smarter
		// but that does have its own issues (types would become incompatible)
		parseRegisterSet(sets.getFirst().get("Registers").getAsJsonArray(), peripheral);

	}

	private static List<JsonObject> getValidRegisterSets(JsonArray array) {

		Set<String> unique = new HashSet<>();
		List<JsonObject> sets = new ArrayList<>();

		for (JsonElement entry : array) {

			JsonObject object = entry.getAsJsonObject();
			JsonElement set = object.get("Registers");
			final JsonElement name = object.get("Name");

			// from what I have seen sometimes sets get duplicated, just ignore them here
			if (name == null || name.isJsonNull() || unique.contains(name.getAsString())) {
				continue;
			}

			if (set == null || !set.isJsonArray()) {
				continue;
			}

			unique.add(name.getAsString());
			sets.add(object);
		}

		return sets;
	}

	private void parseRegisterSet(JsonArray set, Peripheral peripheral) {

		final Set<NamedElement> registers = new TreeSet<>(NamedElement::compareTo);

		for (JsonElement element : set) {

			if (!element.isJsonObject()) {
				continue;
			}

			final JsonObject register = (JsonObject) element;

			if (!register.has("Address")) {
				continue;
			}

			// we prefer original name as that is a better way of detecting arrays
			DataSource source = new DataSource();
			if (register.has("OriginalName")) source.addSource(register.get("OriginalName").getAsString());
			if (register.has("Name")) source.addSource(register.get("Name").getAsString());

			registers.add(new NamedElement(source, register));

		}

		// the json format expects us to ignore "X following entries" this isn't possible in many parsers (including the
		// one we are using - GSON) so we have to do it differently - by leveraging the fact all the array "entries" have
		// predicatable names (all array elements name take the form of <name><index>) to sort the registers (so that we
		// have the one that starts the array first and the elements later) and then see if the name matches to drop registers
		Set<String> arrayBaseNames = new HashSet<>();

		for (NamedElement element : registers) {

			final JsonObject register = element.object;
			final String name = element.getName();

			try {
				final JsonElement array = register.get("ArrayInfo");
				final JsonElement width = register.get("Width");
				final long offset = Long.decode(register.get("Address").getAsString());
				final int bits = width.isJsonNull() ? 0 : Integer.decode(width.getAsString());

				// we could also use "OriginalName" here
				Optional<String> base = element.extractBaseName();

				// skip if we belong to a previously defined array
				if (base.isPresent() && arrayBaseNames.contains(base.get())) {
					continue;
				}

				peripheral.createRegister(name, offset, bits).ifPresent(added -> {
					if (array != null && array.isJsonObject()) {
						JsonObject info = array.getAsJsonObject();

						element.source.forEachNonPrimary(added::addAlias);

						if (info.get("IsArray").getAsBoolean()) {
							int length = info.get("Length").getAsInt();

							// yes we do have arrays of length 0,
							// RDL converter just treats them as a single element, let's do the same
							if (length >= 2) {

								// when a non-array-like (no digit at the end of the name) register is marked as an array the RDL converter (in examples I looked at)
								// ignores the array marking and inserts a single register in its place, same as with array of length 0
								if (base.isPresent()) {
									arrayBaseNames.add(base.get());
									added.setCount(length);
								}
							}
						}

						var fields = register.get("Fields");

						if (fields != null && fields.isJsonArray()) {
							parseFieldSet(fields.getAsJsonArray(), added);
						}
					}
				});
			} catch (Exception e) {
				Msg.error(this, e);
			}

		}
	}

	private void parseFieldSet(JsonArray set, Register register) {

		for (JsonElement element : set) {
			if (element instanceof JsonObject object) {

				final JsonObject range = object.get("Range").getAsJsonObject();

				final long start = range.get("Start").getAsLong();
				final long size = range.get("End").getAsLong() - start + 1;
				final String name = object.get("Name").getAsString();

				register.addField(start, size, name);

			}
		}

	}

	public static class NamedElement implements Comparable<NamedElement> {

		private static final Pattern PATTERN = Pattern.compile("^(.*)([0-9]+)$");

		final DataSource source;
		final JsonObject object;

		public NamedElement(DataSource source, JsonObject object) {
			this.source = source;
			this.object = object;
		}

		public String getName() {
			return source.primary().orElseThrow();
		}

		public Optional<String> extractBaseName() {
			String name = getName().trim();
			Matcher matcher = PATTERN.matcher(name);

			if (!matcher.matches()) {
				return Optional.empty();
			}

			return matcher.group(1).describeConstable();
		}

		@Override
		public int compareTo(NamedElement other) {
			return getName().compareTo(other.getName());
		}

		@Override
		public int hashCode() {
			return getName().hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}

			if (obj instanceof NamedElement other) {
				return getName().equals(other.getName());
			}

			return false;
		}

	}

}
