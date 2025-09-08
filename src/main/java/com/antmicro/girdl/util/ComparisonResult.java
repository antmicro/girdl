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
package com.antmicro.girdl.util;

public final class ComparisonResult {

	private static final ComparisonResult SAME = new ComparisonResult(true, "");

	public final boolean same;
	public final String message;

	private ComparisonResult(boolean same, String message) {
		this.same = same;
		this.message = message;
	}

	public static ComparisonResult same() {
		return SAME;
	}

	public static ComparisonResult different(String why) {
		return new ComparisonResult(false, why);
	}

}
