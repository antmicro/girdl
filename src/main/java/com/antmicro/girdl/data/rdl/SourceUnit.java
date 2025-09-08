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
package com.antmicro.girdl.data.rdl;

import com.antmicro.girdl.util.file.Resource;

import java.util.Optional;

public final class SourceUnit {

	/**
	 * Sometimes internal parser errors can lead us on a path to unknown source units,
	 * if we lack tokens and can do no better than say - "somewhere".
	 */
	public static final SourceUnit UNKNOWN = ofString("<unknown>");

	/**
	 * This should be used when we don't know from what file the source originates from, it should take the form "string \"source\"",
	 * this provides little information later but if we are compiling a short inline string is perfectly valid.
	 */
	public static SourceUnit ofString(String unit) {
		return new SourceUnit(null, unit);
	}

	/**
	 * This should be the default choice, tokenizer uses this when it knows the file the source originates from,
	 * it allows for better error messages (that include the file path) and allows the IncludeResolver to resolve relative paths.
	 */
	public static SourceUnit ofResource(Resource unit) {
		return new SourceUnit(unit, unit.toString());
	}

	private SourceUnit(Resource resource, String string) {
		this.resource = resource;
		this.string = string;
	}

	public final Resource resource;
	public final String string;

	@Override
	public String toString() {
		return string;
	}

	public Optional<Resource> getResource() {
		return Optional.of(resource);
	}

}
