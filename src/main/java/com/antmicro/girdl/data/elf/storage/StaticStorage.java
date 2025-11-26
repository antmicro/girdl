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

import com.antmicro.girdl.data.elf.Storage;

/**
 * Represents elements whose storage doesn't change during program execution,
 * that is, their location doesn't depend on the program counter.
 */
public abstract class StaticStorage extends Storage {

	@Override
	public boolean hasLocation() {
		return true;
	}

	/// Return true if this value doesn't depend on usage location
	public boolean isUseSiteInvariant() {
		return false;
	}

}
