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
package com.antmicro.girdl.util.args;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class ArgsBuilder {

	private String example;
	private final List<Argument> arguments = new ArrayList<>();
	private final Map<String, Argument> fullNameMap = new HashMap<>();
	private final Map<Character, Argument> flagNameMap = new HashMap<>();

	public void register(char flag, String full, ArgType type, String description) {
		Argument argument = new Argument(flag, full, type, description);

		if (full != null && !full.isEmpty()) {
			fullNameMap.put(full, argument);
		}

		if (flag != 0) {
			flagNameMap.put(flag, argument);
		}

		arguments.add(argument);
	}

	public void example(String example) {
		this.example = example;
	}

	public ArgsBuilder() {
		register('h', "help", ArgType.FLAG, "Print this help page");
	}

	public static class Argument {
		final char flag;
		final String full;
		final ArgType type;
		final String description;

		public Argument(char flag, String full, ArgType type, String description) {
			this.flag = flag;
			this.full = full;
			this.type = type;
			this.description = description;
		}

		@Override
		public String toString() {
			return " " + (flag != '\0' ? "-" + flag + ", " : "    ") + "--" + full;
		}

		int length() {
			return toString().length();
		}
	}

	public String help() {

		int max = arguments.stream().mapToInt(Argument::length).max().orElse(0) + 3;
		StringBuilder builder = new StringBuilder();

		builder.append("Available options:\n");

		for (Argument argument : arguments) {

			String prefix = argument.toString();
			String padding = StringUtils.repeat(' ', max - prefix.length());

			builder.append(prefix).append(padding).append(argument.description).append("\n");
		}

		return builder.append(example).toString();
	}

	private Argument find(String option) {
		if (option.startsWith("--")) {
			return fullNameMap.get(option.substring(2));
		}

		if (option.startsWith("-") && option.length() == 2) {
			return flagNameMap.get(option.charAt(1));
		}

		throw new RuntimeException("Invalid syntax for option '" + option + "', options should start with '-' or '--'!");
	}

	private void parse(Args args, Iterator<String> stream) {

		while (stream.hasNext()) {

			String option = stream.next();
			Argument argument = find(option);

			if (argument == null) {
				throw new RuntimeException("Unknown option '" + option + "', see list of available options!");
			}

			List<String> values = args.create(argument.full);

			if (argument.type == ArgType.STRING) {
				if (!stream.hasNext()) {
					throw new RuntimeException("Value not provided for option '" + option + "', expected value!");
				}

				values.add(stream.next());
			}

		}

	}

	public Args parse(String[] argv) {
		try {
			Args args = new Args();
			parse(args, List.of(argv).iterator());
			return args;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			System.out.println(help());

			System.exit(1);
			return null;
		}
	}

}
