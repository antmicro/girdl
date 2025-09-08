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

public final class Macro {

	public final String name;
	public final String value;

	public Macro(String name, String value) {
		this.name = name;
		this.value = value;
	}

	public Macro(String name) {
		this.name = name;
		this.value = "";
	}

	public static Macro parse(String macro) {
		String[] parts = macro.split("=");

		if (parts.length == 1) {
			return new Macro(macro);
		}

		if (parts.length == 2) {
			return new Macro(parts[0], parts[1]);
		}

		throw new RuntimeException("Invalid macro definition syntax, expected \"key=value\" pair or just the key");
	}


}
