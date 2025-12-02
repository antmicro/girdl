# Basics and setup

This chapter describes how to configure Ghidra to work with girdl and how to use it for analysis.

## Plugin setup

To use girdl, download the plugin's `.zip` file and start Ghidra.
Do take note of the plugin's expected Ghidra version, if they don't match the plugin will not load or may crash Ghidra.
Start Ghidra, then click the `File > Install Extensions` option in the top bar. In the popup window click the green plus icon in the top right and select the plugin `.zip`.

Once you added the plugin, press `OK` and **restart Ghidra**, after that the plugin should be available.
If you want to develop girdl, there is a different way to start Ghidra with the plugin. See the [Development](development.md) chapter for details.

## Basic usage

When you open a file for analysis, in the `Analysis Options` dialog scroll the list, find `Peripheral Registers` and make sure it is enabled. Select it and configure it in the panel to the right.
See the [](sources.md) chapter to learn how to provide input data for the plugin.