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

public class Location {

	public static final Location UNKNOWN = new Location(0, 0, SourceUnit.UNKNOWN);

	public final int line;
	public final int column;
	public final SourceUnit unit;

	public Location(int line, int column, SourceUnit unit) {
		this.line = line;
		this.column = column;
		this.unit = unit;
	}

	public final String where() {
		return line + ":" + column + " in " + unit;
	}

}
