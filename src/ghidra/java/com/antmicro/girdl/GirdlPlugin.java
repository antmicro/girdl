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

import com.antmicro.girdl.util.DwarfExporter;
import com.antmicro.girdl.util.GhidraFile;
import com.antmicro.girdl.util.log.Logger;
import com.google.common.base.Stopwatch;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

import java.io.File;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = GirdlPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Registry description plugin",
	description = "Show descriptions of peripheral registers"
)
public class GirdlPlugin extends ProgramPlugin {

	public static final HelpLocation HELP = new HelpLocation("girdl", "GirdlHelp");

	public GirdlPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {

		DockingAction helloAction = new DockingAction("Export DWARF", getName()) {

			private File askForExportFile() {

				GhidraFileChooser chooser = new GhidraFileChooser(null);
				chooser.setTitle("Export DWARF As...");
				chooser.setApproveButtonText("Save As");
				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				chooser.setMultiSelectionEnabled(false);

				File selected = chooser.getSelectedFile(true);
				chooser.dispose();
				if (chooser.wasCancelled()) {
					return null;
				}

				return selected;

			}

			private Optional<Long> askForEntryPoint() {
				EntrypointChooser chooser = new EntrypointChooser();
				tool.showDialog(chooser);

				return chooser.getEntrypointAddress();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				File file = askForExportFile();

				if (file == null) {
					return;
				}

				var entrypoint = askForEntryPoint();
				Stopwatch stopwatch = Stopwatch.createStarted();

				if (entrypoint.isEmpty()) {
					Logger.info(this, "Operation aborted, no mount point selected");
					return;
				}

				try {
					DwarfExporter.dumpProgramDebugInfo(file, currentProgram, entrypoint.orElseThrow());
					Logger.info(this, "Finished writing DWARF data in " + stopwatch.elapsed(TimeUnit.MILLISECONDS) + "ms");
				} catch (Exception e) {
					Logger.error(this, "Can't write to '" + file.getPath() + "': " + e.getMessage());
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}

		};

		helloAction.setEnabled(true);
		helloAction.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_FILE, "Export to DWARF..."}, "Import Export"));

		tool.addAction(helloAction);

	}

	static {
		Logger.setSink(new GhidraLogConsumer());
		GhidraFile.register();

		Logger.info(GirdlPlugin.class, "Plugin systems ready!");
	}

}
