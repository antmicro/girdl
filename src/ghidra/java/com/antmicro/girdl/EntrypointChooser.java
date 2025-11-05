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
import ghidra.util.layout.PairLayout;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class EntrypointChooser extends ReusableDialogComponentProvider {

	private static class Config {
		final String name;
		final long mount;

		private Config(String s, long mount) {
			name = s;
			this.mount = mount;
		}

		@Override
		public String toString() {
			return "0x" + Long.toHexString(mount) + " - " + name;
		}
	}

	private static class CustomConfig extends Config {
		private CustomConfig() {
			super("Custom", 0);
		}

		@Override
		public String toString() {
			return "Use custom mount address";
		}
	}

	private boolean confirmed = false;
	private JTextField addressField;
	private JComboBox entryField;
	private long addressValue;

	private final List<Config> options = new ArrayList<>();

	// The value was obtained by subtracting the entrypoint address
	// in ghidra from the entry point address in gdb with address
	// randomization turned off (this is the default in GDB  on linux).
	// https://visualgdb.com/gdbreference/commands/set_disable-randomization
	private static final long GDB_MOUNT = 0x555555454000L;

	EntrypointChooser() {
		super("DWARF Config");

		options.add(new Config("GDB", GDB_MOUNT));

		// custom config allows for the user to manually enter the program
		// mount point, this allows them to use the plugin even with ASLR
		// enabled (Address Space Layout Randomization)
		options.add(new CustomConfig());

		this.addWorkPanel(this.createPanel());
		this.addOKButton();
		this.addCancelButton();
	}

	protected void cancelCallback() {
		this.close();
	}

	private long getCustomAddress() {
		try {
			return Long.decode(addressField.getText());
		} catch (Exception e) {
			Logger.error(this, "Unable to parse entrypoint address '" + addressField.getText() + "' as long, assuming 0");
			return 0;
		}
	}


	protected void okCallback() {
		Config config = (Config) entryField.getSelectedItem();

		if (config == null) {
			return;
		}

		addressValue = (config instanceof CustomConfig) ? getCustomAddress() : config.mount;
		Logger.info(this, "Using DWARF/ELF mount point: 0x" + Long.toHexString(addressValue));
		confirmed = true;
		this.close();
	}

	private JPanel createPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(new EmptyBorder(10, 10, 10, 10));

		addressField = new JTextField("0", 30);
		addressField.setFont(Font.decode("monospaced"));
		addressField.getAccessibleContext().setAccessibleName("Entrypoint");
		addressField.setToolTipText("Enter the virtual mount address.");
		addressField.setEnabled(false);

		entryField = new JComboBox<>(options.toArray());
		entryField.setFont(Font.decode("monospaced"));
		entryField.getAccessibleContext().setAccessibleName("Offset");
		entryField.setToolTipText("Select the virtual mount address");

		entryField.addItemListener(item -> {
			Config config = (Config) item.getItem();

			addressValue = config.mount;
			addressField.setEnabled(config instanceof CustomConfig);
		});

		panel.add(new JLabel("Mount: "));
		panel.add(entryField);

		panel.add(new JLabel("Custom: "));
		panel.add(addressField);

		return panel;
	}

	public Optional<Long> getEntrypointAddress() {
		return confirmed ? Optional.of(addressValue) : Optional.empty();
	}

}
