# Peripheral types

Once the input files are loaded, girdl extracts data types from all supported data sources, and each peripheral is assigned a struct that matches its register layout (even when no peripheral map was given - see the [](sources.md) chapter).
If the peripheral map was supplied or the data is already included in the input format, the data types get bound to specific addresses corresponding to peripheral binding sites.

Peripheral types can be assigned to variables using the `Retype Variable` menu under `ExecutableFileName > Peripherals`.