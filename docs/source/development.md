# Development

This chapter provides a guide for developers who want to contribute to girdl.

## Easier Ghidra launch

If you are a developer on Linux, you can use the provided `./script/ghidra.sh` script to build and launch (`./script/ghidra.sh -r`) the extension without having to install it manually and restart Ghidra each time.

## License

When adding new files, you can use the `./script/license.sh` script to prepend all Java files without a license in the project with the correct license header.
A license will only be added if the file already starts with Java's `package` keyword.
If some problem is detected, an error will be printed for you to investigate manually.