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
package com.antmicro.girdl.data;

import com.antmicro.girdl.model.Binding;
import com.antmicro.girdl.model.Register;
import com.antmicro.girdl.test.Util;
import com.antmicro.girdl.util.DataSource;
import com.antmicro.girdl.util.file.Resource;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.PrintWriter;
import java.util.List;

public class JsonRegistryImporterTest {

	@Test
	public void testNamedElement() {

		DataSource ds = new DataSource();
		ds.addSource("First0");
		ds.addSource("Second");

		JsonRegisterImporter.NamedElement ne = new JsonRegisterImporter.NamedElement(ds, new JsonObject());

		var opt = ne.extractBaseName();

		Assertions.assertEquals("First0", ne.getName());
		Assertions.assertTrue(opt.isPresent());
		Assertions.assertEquals("First", opt.get());

	}

	@Test
	public void testSimpleJsonImport() {
		File binding = Util.createTempFile(".json");
		File definitions = Util.createTempFile("Test.", "-registersInfo.json");
		PrintWriter bindingWriter = Util.getFileWriter(binding);
		PrintWriter definitionsWriter = Util.getFileWriter(definitions);

		bindingWriter.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": null}");
		bindingWriter.close();

		definitionsWriter.println("[{\"Name\": \"RegisterBank1\", \"Registers\": [");
		definitionsWriter.println("	{\"Name\": \"A\", \"Address\": 13, \"Width\": 32}");
		definitionsWriter.println("]}]");
		definitionsWriter.close();

		Importer importer = Importer.of(Resource.fromJavaFile(binding), Resource.fromJavaFile(definitions));

		Context context = new Context();
		importer.load(context);
		context.compile();

		Assertions.assertEquals(1, context.getPeripheralMap().get("Test").registers.size());
	}

	@Test
	public void testMappedJsonImport() {
		File binding = Util.createTempFile(".json");
		PrintWriter bindingWriter = Util.getFileWriter(binding);

		bindingWriter.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		bindingWriter.println("	{\"Name\": \"Test\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 100} ], \"Children\": []},");
		bindingWriter.println("	{\"Name\": \"Test\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 200} ], \"Children\": []},");
		bindingWriter.println("	{\"Name\": \"Test\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 300} ], \"Children\": []}");
		bindingWriter.println("]}}");
		bindingWriter.close();

		File definitions = Util.createTempFile("Test", "-registryInfo.json");
		PrintWriter definitionsWriter = Util.getFileWriter(definitions);

		definitionsWriter.println("[{\"Name\": \"A\", \"Address\": 13, \"Width\": 32}]");
		definitionsWriter.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(definitions), Resource.fromJavaFile(binding)).load(context);
		context.compile();
		List<Binding> bindings = context.getPeripheralMap().get("Test").bindings;

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Assertions.assertEquals(3, bindings.size());
		Util.sameCollection(bindings.stream().map(bind -> bind.address).toList(), List.of(100L, 200L, 300L));
		Util.sameCollection(bindings.stream().map(bind -> bind.name).toList(), List.of("Test", "Test_1", "Test_2"));
	}

	@Test
	public void testBindingsJsonImport() {
		File binding = Util.createTempFile(".json");
		PrintWriter bindingWriter = Util.getFileWriter(binding);

		bindingWriter.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		bindingWriter.println("	{\"Name\": \"Test\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 100}, {\"Type\": \"Bus\", \"Value\": 200}, {\"Type\": \"Bus\", \"Value\": 300} ], \"Children\": []}");
		bindingWriter.println("]}}");
		bindingWriter.close();

		File definitions = Util.createTempFile("Test.", "-registersInfo.json");
		PrintWriter definitionsWriter = Util.getFileWriter(definitions);

		definitionsWriter.println("[{\"Name\": \"RegisterBank1\", \"Registers\": [");
		definitionsWriter.println("	{\"Name\": \"A\", \"Address\": 13, \"Width\": 32}");
		definitionsWriter.println("]}]");
		definitionsWriter.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(binding), Resource.fromJavaFile(definitions)).load(context);
		context.compile();


		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Assertions.assertTrue(context.getPeripheralMap().containsKey("Test"));

		List<Register> registers = context.getPeripheralMap().get("Test").registers;
		List<Binding> bindings = context.getPeripheralMap().get("Test").bindings;

		Assertions.assertEquals(1, registers.size());
		Assertions.assertEquals(3, bindings.size());

		Util.sameCollection(bindings.stream().map(bind -> bind.address).toList(), List.of(100L, 200L, 300L));
		Util.sameCollection(bindings.stream().map(bind -> bind.name).toList(), List.of("Test", "Test_1", "Test_2"));

	}

	@Test
	public void testJsonImportDuplicateResolution() {
		File definitions1 = Util.createTempFile("Test.", "-registersInfo.json");
		File definitions2 = Util.createTempFile("Test.", "-registersInfo.json");

		{
			PrintWriter definitionsWriter = Util.getFileWriter(definitions1);
			definitionsWriter.println("[{\"Name\": \"RegisterBank1\", \"Registers\": [");
			definitionsWriter.println("	{\"Name\": \"A\", \"Address\": 13, \"Width\": 32}");
			definitionsWriter.println("]}]");
			definitionsWriter.close();
		}

		{
			PrintWriter definitionsWriter = Util.getFileWriter(definitions2);
			definitionsWriter.println("[{\"Name\": \"RegisterBank1\", \"Registers\": [");
			definitionsWriter.println("	{\"Name\": \"B\", \"Address\": 13, \"Width\": 32}");
			definitionsWriter.println("]}]");
			definitionsWriter.close();
		}

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(definitions1), Resource.fromJavaFile(definitions2)).load(context);
		context.compile();


		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Assertions.assertTrue(context.getPeripheralMap().containsKey("Test"));

		List<Register> registers = context.getPeripheralMap().get("Test").registers;
		List<Binding> bindings = context.getPeripheralMap().get("Test").bindings;

		Assertions.assertEquals(1, registers.size());
		Assertions.assertEquals(0, bindings.size());

		// 'B' was added later so it would have been discarded upon being submitted to the context
		Assertions.assertEquals("A", registers.getFirst().name);

	}

	@Test
	public void testJsonImportSkipInvalidBanks() {
		File definitions = Util.createTempFile("Test.", "-registersInfo.json");

		{
			PrintWriter definitionsWriter = Util.getFileWriter(definitions);
			definitionsWriter.println("[{\"Name\": \"RegisterBank1\", \"Registers\": null}, {\"Name\": \"RegisterBank2\", \"Registers\": [{\"Name\": \"A\", \"Address\": 13, \"Width\": 32}]}, {\"Name\": \"RegisterBank2\", \"Registers\": [{\"Name\": \"B\", \"Address\": 13, \"Width\": 32}]}]");
			definitionsWriter.close();
		}

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(definitions)).load(context);
		context.compile();

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Assertions.assertTrue(context.getPeripheralMap().containsKey("Test"));

		List<Register> registers = context.getPeripheralMap().get("Test").registers;
		List<Binding> bindings = context.getPeripheralMap().get("Test").bindings;

		Assertions.assertEquals(1, registers.size());
		Assertions.assertEquals(0, bindings.size());

		// 'B' was added later so it would have been discarded during set filtering
		Assertions.assertEquals("A", registers.getFirst().name);

	}

}
