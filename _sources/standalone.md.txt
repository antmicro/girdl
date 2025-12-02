# Standalone Mode

Girdl supports a so-called "standalone mode" that allows you to access some of the plugin features, without starting ghidra, from the terminal.
To access the standalone mode take the plugin .zip file and unpack it, then in same directory run `java -jar girdl/lib/girdl.jar --help` to see the available options.
```bash
# First unpack the girdl.zip file with any archive manager
unzip girdl.zip

# print the list of available commands
java -jar girdl/lib/girdl.jar --help
```

When invoking girdl in standalone mode always put the program arguments after the jar path! All arguments placed before that will get passed to Java itself, not girdl.

## Usage

girdl in standalone mode can be used to convert RDL and SVD files into DWARF ELF files for use in debuggers.

```bash
# Generates 'symbols.dwarf' by default unless an explicit --output/-o flag is given
java -jar girdl/lib/girdl.jar -i ~/rdl/
```