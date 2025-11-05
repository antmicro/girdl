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
package com.antmicro.girdl.data.elf.storage;

/**
 * Represents elements that aren't stored in any memory,
 * and instead should be treated as named constants.
 */
public class ConstStorage extends StaticStorage {

	public final long value;

	public ConstStorage(long offset) {
		this.value = offset;
	}

	public boolean hasLocation() {
		return false;
	}

}
