# girdl

Copyright (c) 2025 [Antmicro](https://www.antmicro.com)

<img width="353" height="147" alt="girdl-logo-color" src="https://github.com/user-attachments/assets/8b41fafc-225b-4c11-b1bd-e24ae1df5e1d" />

`girdl` is a plugin for [Ghidra](https://github.com/NationalSecurityAgency/ghidra) for automatic analysis of the binding of individual registers and their layouts.

## Building

To build the extension, use the provided Gradle wrapper script:

```bash
# Before you can build the plugin you will need to run the install.sh script
# to download a local copy of ghidra that the plugin is based on
./script/install.sh

# Extension zip will be created in ./dist
# To use it add it to the list found in File > Install Extensions, and restart ghidra
./gradlew build
```

If you just intend to run/debug the plugin and don't care about adding it to your own Ghidra install:

```bash
# This will start ghidra with the extension pre-installed,
# this is the recommended way of starting the plugin during development
./script/ghidra.sh -r
```

## Usage

When you begin file analysis (with the plugin enabled), in the "Analysis Options" popup scroll to "Peripheral Registers" and specify the path to a `.json`, `.svd`, or `.rdl` file containing the definitions of the registers (or a directory/archive to load multiple files).

Additional help can be found under "Help > Contents > Ghidra Functionality > Peripheral Registers" and in the [Documentation](docs/source/index.md).

## Testing

This plugin uses submodules for some of the test data, but if you don't want to use them you can still run the tests, those that depend on the submodule data will be skipped.

```bash
# If you want to clone the submodules with additional test data use:
git submodule update --init --recursive

# Run checkstyle and unit tests
./gradlew check

# Additionally, run tests of the standalone mode
./script/ci/standalone.sh
```

## Development

Want to help develop girdl? See the [Development Guide](docs/source/development.md).

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
