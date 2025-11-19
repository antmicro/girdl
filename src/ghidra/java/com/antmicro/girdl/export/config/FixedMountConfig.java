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
package com.antmicro.girdl.export.config;

import javax.swing.*;

/**
 * Fixed config allows the user to easily select the desired target
 * mount point of the executable from a list, as with ASLR
 * being disabled by default in debuggers this value does not change.
 */
public class FixedMountConfig implements MountConfig {

	private final String name;
	private final long mount;

	public FixedMountConfig(String name, long mount) {
		this.name = name;
		this.mount = mount;
	}

	@Override
	public String toString() {
		return "0x" + Long.toHexString(mount) + " - " + name;
	}

	@Override
	public boolean enableManualInput() {
		return false;
	}

	@Override
	public long getForManualInput(JTextField address) {
		return mount;
	}

}
