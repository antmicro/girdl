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

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = GirdlPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Registry description plugin",
	description = "Show descriptions of peripheral registers"
)
public class GirdlPlugin extends ProgramPlugin {

	public static final HelpLocation HELP = new HelpLocation("girdl", "GirdlHelp");

	public GirdlPlugin(PluginTool tool) {
		super(tool);
	}

}
