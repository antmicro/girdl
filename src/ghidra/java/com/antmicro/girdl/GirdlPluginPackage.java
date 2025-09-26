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
package com.antmicro.girdl;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class GirdlPluginPackage extends PluginPackage {

	/// This value MUST be uppercase as it's used as a class name
	public static final String NAME = "Girdl";
	private static final String DESCRIPTION = "Peripheral registers plugin.";

	public GirdlPluginPackage() {
		super(NAME, ResourceManager.loadImage("images/girdl-icon.png"), DESCRIPTION, FEATURE_PRIORITY);
	}
}
