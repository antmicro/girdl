# girdl

Copyright (c) 2025 [Antmicro](https://www.antmicro.com)

<img width="353" height="147" alt="girdl-logo-color" src="https://github.com/user-attachments/assets/8b41fafc-225b-4c11-b1bd-e24ae1df5e1d" />

`girdl` is a plugin for [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for automatic analysis of the binding of individual registers and their layouts.

## Building

To build the extension, use the provided Gradle wrapper script:

```bash
# Specify path to your Ghidra installation directory
# If you build Ghidra from source this will be under <ghidra>/build/dist/ghidra_<version>
export GHIDRA_INSTALL_DIR="..."

# Extension file will be created in ./dist
# To use it place it in GHIDRA_INSTALL_DIR/Extensions/Ghidra or ...
./gradlew distributeExtension

# Run this target to copy the extension to the given Ghidra installation
# After this, in Ghidra, go to File > Install Extensions and select 'renode' from the list
./gradlew applyExtension
```

## Usage

When you begin file analysis (with the plugin enabled), in the "Analysis Options" popup scroll to "Peripheral Registers" and specify the path to a `.json`, `.svd`, or `.rdl` file containing the definitions of the registers (or a directory/archive to load multiple files).

Additional help can be found under *Help > Contents > Ghidra Functionality > Peripheral Registers* and in the [Documentation](docs/index.md).

## Testing

This plugin uses submodules for some of the test data, but if you don't want to use them you can still run the tests, those that depend on the submodule data will be skipped.

```bash
# If you want to clone the submodules with additional test data use:
git submodule update --init --recursive

# Run tests
./gradlew test --rerun
```

## Development

Want to help develop girdl? See the [Development Guide](docs/source/development.md).

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
