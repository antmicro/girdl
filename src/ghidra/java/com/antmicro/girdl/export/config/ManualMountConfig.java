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

import com.antmicro.girdl.util.log.Logger;

import javax.swing.*;

/**
 * Custom config allows for the user to manually enter the program
 * mount point, this allows them to use the plugin even with ASLR
 * enabled (Address Space Layout Randomization)
 */
public class ManualMountConfig implements MountConfig {

	private final String message;

	public ManualMountConfig(String message) {
		this.message = message;
	}

	@Override
	public String toString() {
		return message;
	}

	@Override
	public boolean enableManualInput() {
		return true;
	}

	@Override
	public long getForManualInput(JTextField address) {
		String text = address.getText();

		try {
			return Long.decode(text);
		} catch (Exception e) {
			Logger.error(this, "Unable to parse entrypoint address '" + text + "' as long, assuming 0");
			return 0;
		}
	}

}
