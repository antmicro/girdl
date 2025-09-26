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

import com.antmicro.girdl.data.Context;
import com.antmicro.girdl.data.Importer;
import com.antmicro.girdl.data.elf.DwarfFile;
import com.antmicro.girdl.data.elf.enums.ElfMachine;
import com.antmicro.girdl.data.rdl.Macro;
import com.antmicro.girdl.model.Peripheral;
import com.antmicro.girdl.util.args.ArgType;
import com.antmicro.girdl.util.args.Args;
import com.antmicro.girdl.util.args.ArgsBuilder;
import com.antmicro.girdl.util.file.Resource;
import com.antmicro.girdl.util.log.Logger;
import com.antmicro.girdl.util.log.StandaloneLogConsumer;
import org.apache.commons.lang3.SystemUtils;

import java.io.File;
import java.util.Collection;

public class Standalone {

	public static final String DEFAULT_OUTPUT = "symbols.dwarf";

	private static String preparePath(String path) {
		if (SystemUtils.IS_OS_UNIX) {
			String home = System.getProperty("user.home");

			if (!home.isBlank()) {
				return path.replaceAll("~", home);
			}
		}

		return path;
	}

	public static void main(String[] argv) {

		ArgsBuilder builder = new ArgsBuilder();
		builder.register('\0', "allow-remote", ArgType.FLAG, "Permit the usage of URLs as inputs");
		builder.register('i', "input", ArgType.STRING, "Path to peripherals definitions (SVD, RDL, ...)");
		builder.register('o', "output", ArgType.STRING, "Path to output DWARF file, defaults to '" + DEFAULT_OUTPUT + "'");
		builder.register('q', "quiet", ArgType.FLAG, "Produce less debug output");
		builder.register('D', "define", ArgType.STRING, "Provide a macro definition for RDL compiler");
		builder.register('A', "address", ArgType.STRING, "Mount address offset added to each binding");

		// CHECKSTYLE:OFF
		builder.example("""
				
				Example:
				 girdl -i rtc.rdl -i uart.rdl --output symbols.dwarf
				 girdl -i rtc.rdl -i i3c.rdl -D CONTROLLER_SUPPORT -D FOO=123
				""");
		// CHECKSTYLE:ON

		Args args = builder.parse(argv);

		if (args.hasFlag("help")) {
			System.out.println(builder.help());
			System.exit(0);
		}

		StandaloneLogConsumer consumer = new StandaloneLogConsumer(System.out);
		consumer.trace = !args.hasFlag("quiet");
		Logger.setSink(consumer);

		Context context = new Context();

		long entrypoint = args.getOption("address").map(Long::decode).orElse(0L);
		File output = args.getOption("output").map(File::new).orElseGet(() -> new File(DEFAULT_OUTPUT));
		Resource[] inputs = args.getOptions("input").stream().map(Standalone::preparePath).map(args.hasFlag("allow-remote") ? Resource::fromUniversalPath : Resource::fromLocalPath).toArray(Resource[]::new);
		context.macros = args.getOptions("define").stream().map(Macro::parse).toList();

		Importer.of(inputs).load(context);
		context.compile();

		Collection<Peripheral> peripherals = context.getPeripheralMap().values();

		if (peripherals.isEmpty()) {
			Logger.warn(Standalone.class, "No peripherals created! Is the input data correct?");
		}

		try (DwarfFile dwarf = new DwarfFile(output, ElfMachine.I386, 32)) {
			peripherals.forEach(peripheral -> dwarf.createPeripheral(peripheral, entrypoint));
		}

	}

}
