# Data Export

The plugin can be used to generate debugger information for the analyzed executable directly from Ghidra.
The "File > Export to DWARF..." option creates an auxiliary ELF file in the selected location that contains DWARF data generated from Ghidra.
The whole process is described step-by-step below:

1) File > Export to DWARF...
2) Select target file location
3) Select what you want to export (don't change the setting to export everything)
4) Click OK
3) Load your executable into GDB (or alternative debugger)
4) Use the `add-symbol-file <path>` command with the path to the generated file.

You should now be able to use the generated debug symbols in the debugging session.