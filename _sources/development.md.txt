# Development

This chapter provides a guide for developers who want to contribute to girdl.

## Easier Ghidra launch

If you are a developer on Linux, you can use the provided `./script/ghidra.sh` script to build and launch (`./script/ghidra.sh -r`) the extension without having to install it manually and restart Ghidra each time.
You can also use the `-d` flag (`./script/ghidra.sh -d`) to run ghidra in debug-suspend mode where it will wait for you to attach the debugger.
Remember to first install a local copy of Ghidra using `./script/install.sh` before you try building the extension.

```{warning}
The GirdlPlugin constructor will only be invoked (thus add GUI elements, such as menu bar items) if the plugin is "Configured".
If you weren't automatically prompted to do so go to 'File > Configure > Girdl' (once you open a project!) and select the checkbox next to the girdl entry.
After this restart and reopen the project, this setting should persist though restarts and rebuilds of the plugin.
```

## License

When adding new files, you can use the `./script/license.sh` script to prepend all Java files without a license in the project with the correct license header.
A license will only be added if the file already starts with Java's `package` keyword.
If some problem is detected, an error will be printed for you to investigate manually.