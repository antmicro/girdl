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

import com.antmicro.girdl.data.rdl.Macro;
import com.antmicro.girdl.util.file.Resource;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class GirdlOptions {

	public static final String RENODE_LATEST_URL = "https://builds.renode.io/renode-latest.rdl.tar.gz";

	// names
	static private final String FILE_SOURCE_1 = "Data Source 1";
	static private final String FILE_SOURCE_2 = "Data Source 2";
	static private final String RDL_MACROS    = "RDL Macros";
	static private final String RDL_RENODE    = "Use Renode RDL";

	// values
	private String firstPath = null;
	private String secondPath = null;
	private String macros = null;
	private boolean renode = false;

	public void register(Options options) {
		options.registerOption(FILE_SOURCE_1, OptionType.STRING_TYPE, "", GirdlPlugin.HELP, "Registry definitions file path", GirdlFileChooser::new);
		options.registerOption(FILE_SOURCE_2, OptionType.STRING_TYPE, "", GirdlPlugin.HELP, "Peripheral definitions file path", GirdlFileChooser::new);
		options.registerOption(RDL_MACROS, OptionType.STRING_TYPE, "VARIANT0", GirdlPlugin.HELP, "List of macro definition to be provided to the RDL parser, ';' separated");
		options.registerOption(RDL_RENODE, OptionType.BOOLEAN_TYPE, false, GirdlPlugin.HELP, "Load registry definitions from the latest Renode release");
	}

	public void update(Options options) {
		firstPath = options.getString(FILE_SOURCE_1, firstPath);
		secondPath = options.getString(FILE_SOURCE_2, secondPath);
		macros = options.getString(RDL_MACROS, macros);
		renode = options.getBoolean(RDL_RENODE, renode);
	}

	private List<String> getPathSet() {
		List<String> urls = new ArrayList<>(4);

		urls.add(firstPath);
		urls.add(secondPath);

		if (renode) {
			urls.add(RENODE_LATEST_URL);
		}

		return urls;
	}

	public Resource[] getSourceSet() {
		return getPathSet().stream().map(Resource::fromUniversalPath).toArray(Resource[]::new);
	}

	public List<Macro> getMacros() {
		return Arrays.stream(macros.split(";")).sequential().map(Macro::parse).toList();
	}

}
