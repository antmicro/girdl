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
package com.antmicro.girdl.export;

import com.antmicro.girdl.export.config.FixedMountConfig;
import com.antmicro.girdl.export.config.ManualMountConfig;
import com.antmicro.girdl.export.config.MountConfig;
import com.antmicro.girdl.util.log.Logger;
import docking.ReusableDialogComponentProvider;
import ghidra.util.layout.PairLayout;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;
import java.util.Optional;

public class DwarfExportConfigProvider extends ReusableDialogComponentProvider {

	// The value was obtained by subtracting the entrypoint address
	// in ghidra from the entry point address in gdb with address
	// randomization turned off (this is the default in GDB  on linux).
	// https://visualgdb.com/gdbreference/commands/set_disable-randomization
	private static final long GDB_MOUNT = 0x555555454000L;

	// Help message shown below the address dropdown
	private static final String DESCRIPTION = """
			The mount address describes where the process is mounted in memory, not its entrypoint.
			On Linux debuggers this is by default kept constant for convenience.
			This value can be calculated by subtracting the entrypoint address shown in Ghidra from the one shown in GDB after process startup.
			""";

	private boolean confirmed = false;
	private long address = 0;

	private JTextField addressField;
	private JComboBox<MountConfig> entryField;

	private JCheckBox doExportFunctionVariables;
	private JCheckBox doExportFunctionParameters;
	private JCheckBox doExportSourceMap;
	private JCheckBox doExportUnusedTypes;
	private JCheckBox doExportEquates;
	private JComboBox<DwarfExportGlobals> symbolExportScope;

	private List<MountConfig> getOptionSet() {
		return List.of(
				new FixedMountConfig("GDB", GDB_MOUNT),
				new ManualMountConfig("Use custom mount address")
		);
	}

	public DwarfExportConfigProvider() {
		super("DWARF Config");

		JPanel panel = createPanel(getOptionSet());

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
	}

	protected void okCallback() {
		MountConfig config = (MountConfig) entryField.getSelectedItem();

		if (config == null) {
			return;
		}

		address = config.getForManualInput(addressField);
		Logger.info(this, "Selected DWARF/ELF mount point: 0x" + Long.toHexString(address));

		confirmed = true;
		close();
	}

	private JPanel createPanel(List<MountConfig> options) {
		JPanel outer = new JPanel(new GridLayout(1, 2));
		JPanel leftTopDown = new JPanel(new GridLayout(2, 1));

		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		entryField = new JComboBox<>(options.toArray(MountConfig[]::new));
		entryField.setFont(Font.decode("monospaced"));
		entryField.getAccessibleContext().setAccessibleName("Mount");
		entryField.setToolTipText("Select the virtual mount address");

		entryField.addItemListener(item -> {
			MountConfig config = (MountConfig) item.getItem();
			addressField.setEnabled(config.enableManualInput());
		});

		panel.add(new JLabel("Mount: "));
		panel.add(entryField);

		addressField = new JTextField("0", 30);
		addressField.setFont(Font.decode("monospaced"));
		addressField.getAccessibleContext().setAccessibleName("Address");
		addressField.setToolTipText("Enter the virtual mount address");
		addressField.setEnabled(false);

		panel.add(new JLabel("Custom: "));
		panel.add(addressField);

		JTextArea description = new JTextArea(DESCRIPTION.replace('\n', ' '));
		description.setLineWrap(true);
		description.setWrapStyleWord(true);
		description.setEditable(false);
		description.setBorder(new EmptyBorder(0, 0, 0, 5));

		// we use a scroll pane here to stop JTextArea from filling the entire screen vertically
		// as that would otherwise happen when text wrap is enabled...
		JScrollPane isolation = new JScrollPane(description);
		isolation.setFocusable(false);
		isolation.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		isolation.setBorder(new EmptyBorder(0, 10, 0, 10));

		leftTopDown.add(panel);
		leftTopDown.add(isolation);

		JPanel inner = new JPanel(new GridLayout(0, 1));

		doExportFunctionVariables = new JCheckBox("Function variables", true);
		doExportFunctionParameters = new JCheckBox("Function parameters", true);
		doExportSourceMap = new JCheckBox("Source code mapping", true);
		doExportUnusedTypes = new JCheckBox("Export unused types", true);
		doExportEquates = new JCheckBox("Export Ghidra equates", true);
		symbolExportScope = new JComboBox<>(DwarfExportGlobals.values());

		inner.add(new JLabel("<html><b>Elements To Export</b></html>"));
		inner.add(doExportFunctionVariables);
		inner.add(doExportFunctionParameters);
		inner.add(doExportSourceMap);
		inner.add(doExportUnusedTypes);
		inner.add(doExportEquates);
		inner.add(symbolExportScope);

		outer.add(leftTopDown);
		outer.add(inner);

		return outer;
	}

	public Optional<DwarfExportConfig> getDwarfConfig() {

		if (!confirmed) {
			return Optional.empty();
		}

		return Optional.of(new DwarfExportConfig(
				address,
				doExportFunctionVariables.isSelected(),
				doExportFunctionParameters.isSelected(),
				doExportSourceMap.isSelected(),
				doExportUnusedTypes.isSelected(),
				doExportEquates.isSelected(),

				// we shouldn't need the cast here, but old java code of Swing
				// doesn't use sensible generics so we must use it
				(DwarfExportGlobals) symbolExportScope.getSelectedItem()
		));
	}

}
