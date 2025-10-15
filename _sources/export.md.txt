# Data Export

The plugin can be used to generate debugger information for the analyzed executable directly from Ghidra.
The "File > Export to DWARF..." option creates an auxiliary ELF file in the selected location that contains DWARF data generated from Ghidra.
The whole process is described step-by-step below:

1) File > Export to DWARF...
2) Select target file location
3) Load your executable into GDB (or alternative debugger)
4) Use the `starti` command to load the program into memory and stop at the first instruction
5) Use the `info file` command and copy the "Entrypoint" value, (this **needs** to be done after step 4)
6) Paste the value into the "Entrypoint" text box in Ghidra
7) Select the entrypoint function from the dropdown menu "Offset", this will typically be the function called "entry"

Then to import this data into GDB, use the `add-symbol-file <path>` command with the path to the generated file.