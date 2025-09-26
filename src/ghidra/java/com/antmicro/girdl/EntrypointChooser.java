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

import com.antmicro.girdl.util.log.Logger;
import docking.ReusableDialogComponentProvider;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.PairLayout;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class EntrypointChooser extends ReusableDialogComponentProvider {

	private JTextField addressField;
	private JComboBox entryField;
	private long addressValue;
	private List<Long> offsets = new ArrayList<>();

	EntrypointChooser(Program program) {
		super("DWARF Config");

		List<String> entries = new ArrayList<>();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);

		while (functions.hasNext()) {
			var function = functions.next();
			long address = function.getEntryPoint().getOffset();

			if (function.getSymbol().isExternalEntryPoint()) {
				entries.add("0x" + Long.toHexString(address) + " - " + function.getName());
				offsets.add(address);
			}
		}

		this.addWorkPanel(this.createPanel(entries));
		this.addOKButton();
		this.addCancelButton();
	}

	protected void cancelCallback() {
		this.close();
	}

	protected void okCallback() {

		try {
			addressValue = Long.decode(addressField.getText());
		} catch (Exception e) {
			Logger.error(this, "Unable to parse entrypoint address '" + addressField.getText() + "' as long, assuming 0");
			addressValue = 0;
		}

		addressValue -= offsets.get(entryField.getSelectedIndex());

		Logger.info(this, "Using DWARF/ELF mount point: 0x" + Long.toHexString(addressValue));
		this.close();
	}

	private JPanel createPanel(List<String> entries) {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		addressField = new JTextField("0", 30);
		addressField.setFont(Font.decode("monospaced"));
		addressField.getAccessibleContext().setAccessibleName("Entrypoint");
		addressField.setToolTipText("Enter the address the program's entrypoint is mounted at, you can use hexadecimal notation.\nIn GDB this is the value reported as 'entrypoint' by the 'info file' command AFTER the program is started.");

		panel.add(new JLabel("Entrypoint: "));
		panel.add(addressField);

		entryField = new JComboBox<>(entries.toArray());
		entryField.setFont(Font.decode("monospaced"));
		entryField.getAccessibleContext().setAccessibleName("Offset");
		entryField.setToolTipText("Select the same entrypoint as above, but as it is visible in Ghidra");

		panel.add(new JLabel("Offset: "));
		panel.add(entryField);

		return panel;
	}

	public long getEntrypointAddress() {
		return addressValue;
	}

}
