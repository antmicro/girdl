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

import com.antmicro.girdl.export.DwarfExportConfig;
import com.antmicro.girdl.export.DwarfExportConfigProvider;
import com.antmicro.girdl.export.DwarfExporter;
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
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

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

		DockingAction action = new DockingAction("Export DWARF", getName()) {

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

			private Optional<DwarfExportConfig> askForDwarfConfig() {
				DwarfExportConfigProvider chooser = new DwarfExportConfigProvider();
				tool.showDialog(chooser);

				return chooser.getDwarfConfig();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				File file = askForExportFile();

				if (file == null) {
					return;
				}

				var optional = askForDwarfConfig();

				if (optional.isEmpty()) {
					Logger.info(this, "Operation aborted");
					return;
				}

				TaskLauncher.launch(new Task("Exporting DWARF", true, true, false) {

					@Override
					public void run(TaskMonitor monitor) {
						monitor.setMessage("Exporting DWARF...");
						Stopwatch stopwatch = Stopwatch.createStarted();

						try {
							DwarfExporter.dumpProgramDebugInfo(file, currentProgram, optional.get(), monitor);
							Logger.info(this, "Finished writing DWARF data in " + stopwatch.elapsed(TimeUnit.MILLISECONDS) + "ms");
						} catch (Exception e) {
							Msg.showError(this, null, "DWARF Export", "Can't finish writing to '" + file.getPath() + "'", e);
						}
					}

				});
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}

		};

		action.setEnabled(true);
		action.setMenuBarData(new MenuData(new String[] {ToolConstants.MENU_FILE, "Export to DWARF..."}, "Import Export"));

		tool.addAction(action);

	}

	static {
		Logger.setSink(new GhidraLogConsumer());
		GhidraFile.register();

		Logger.info(GirdlPlugin.class, "Plugin systems ready!");
	}

}
