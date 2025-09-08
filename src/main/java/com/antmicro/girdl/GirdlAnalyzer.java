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
import com.antmicro.girdl.util.Lazy;
import com.antmicro.girdl.util.RecursiveTaskMonitor;
import com.google.common.base.Stopwatch;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

public class GirdlAnalyzer extends AbstractAnalyzer {

	private final Lazy<CategoryPath> category = new Lazy<>();
	private final GirdlOptions config = new GirdlOptions();
	private long lastTxId = -1;

	private static final String DESCRIPTION = """
		Create data structures and bindings of peripherals. The two data sources are completely interchangeable and \
		are provided only for convenience, as the plugin loads data recursively without a predefined order. You can \
		specify URLs, directories, archives, SVD, JSON, and RDL files to load in both of them. Additionally the "Use \
		Renode RDL" option can be used to import data from the most recent Renode build in addition to the sources \
		already specified. For RDL/JSON data you will most likely need to point the plugin (using one of the sources) \
		at a valid PERIPHERAL MAP that was exported from Renode using `peripherals export @<path>`, otherwise the plugin \
		will only load the types and won't create bindings in program memory. For SVD import you don't need anything \
		beside the SVD file itself. \
		""";

	public GirdlAnalyzer() {
		super("Peripheral Registers", DESCRIPTION, AnalyzerType.BYTE_ANALYZER);

		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true; // Return true if analyzer should be enabled by default
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true; // Determine if we should be analyzing given program
	}

	@Override
	public void registerOptions(Options options, Program program) {
		config.register(options);
		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		config.update(options);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {

		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			// Only run once per analysis session - as denoted by being in the same transaction
			return true;
		}
		lastTxId = txId;

		Context context = loadContextFromSettings(monitor);

		monitor.setMessage("Peripheral Definitions - Compiling");
		monitor.setIndeterminate(true);
		context.compile();

		// don't run unless we have something to mark
		if (context.getPeripheralMap().isEmpty()) {
			Msg.info(this, "No peripherals to import, skipping.");
			return false;
		}

		monitor.setMessage("Peripheral Definitions - Applying");
		monitor.setIndeterminate(false);
		monitor.initialize(getTotalBindingCount(context));

		context.getPeripheralMap().values().forEach(peripheral -> {

			final DataType type = peripheral.getType();
			final boolean broken = peripheral.hasNoRegisters();

			addTypeDefinition(program, type, log);

			peripheral.bindings.forEach(binding -> {
				final Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(binding.address, false);

				createMemoryBlock(program, address, type.getLength(), "PERIPHERAL_" + peripheral.name, peripheral.getDescription(), log);
				addPrimarySymbol(program, address, binding.name, log);

				if (!broken) {
					addDataTypeAt(program, address, type, log);
				}

				monitor.incrementProgress();
			});


		});

		return true;
	}

	private Context loadContextFromSettings(TaskMonitor monitor) {

		Stopwatch stopwatch = Stopwatch.createStarted();
		RecursiveTaskMonitor recursive = new RecursiveTaskMonitor(monitor, "Peripheral Definitions - Importing");
		Context context = new Context();
		context.macros = config.getMacros();

		Importer.of(config.getSourceSet()).load(context, recursive);

		long milliseconds = stopwatch.elapsed(TimeUnit.MILLISECONDS);
		Msg.info(this, "Scanned " + recursive.getCount() + " files in " + milliseconds + "ms");

		monitor.setMessage("Peripheral Definitions - Compiling");
		monitor.setIndeterminate(true);
		context.compile();

		return context;

	}

	private int getTotalBindingCount(Context context) {
		return context.getPeripheralMap().values().stream().mapToInt(peripheral -> peripheral.bindings.size()).sum();
	}

	private void createMemoryBlock(Program program, Address start, long length, String name, String comment, MessageLog log) {
		var block = program.getMemory().getBlock(start);

		if (block == null) {
			final boolean read = true;
			final boolean write = true;
			final boolean execute = false;

			MemoryBlockUtils.createUninitializedBlock(program, false, name, start, length, comment, "", read, write, execute, log);
		}
	}

	private void addTypeDefinition(Program program, DataType type, MessageLog log) {
		final DataTypeManager manager = program.getDataTypeManager();

		try {
			type.setCategoryPath(category.getOrCompute(() -> {
				CategoryPath path = new CategoryPath(CategoryPath.ROOT, "Peripherals");

				if (!manager.containsCategory(path)) {
					manager.createCategory(path);
				}

				return path;
			}));
		} catch (Exception e) {
			log.appendException(e);
		}

		manager.addDataType(type, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
	}

	private void addPrimarySymbol(Program program, Address start, String name, MessageLog log) {
		try {
			program.getSymbolTable().createLabel(start, name, SourceType.ANALYSIS).setPrimary();
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void addDataTypeAt(Program program, Address start, DataType type, MessageLog log) {
		try {
			Data data = program.getListing().getDataAt(start);
			boolean undefined = Objects.isNull(data) || Undefined.isUndefined(data.getDataType());

			if (undefined) {
				DataUtilities.createData(program, start, type, -1, DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
		} catch (Exception e) {
			log.appendException(e);
		}
	}

}
