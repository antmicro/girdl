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

import com.antmicro.girdl.test.Util;
import com.antmicro.girdl.util.file.Resource;
import com.google.gson.internal.Streams;
import com.google.gson.stream.JsonReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.List;

public class JsonBindingImporterTest {

	@Test
	public void testBindingImportReadInvalid() throws FileNotFoundException {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Invalid Data\", \"Root\": null}");
		writer.close();

		JsonBindingImporter pmap = new JsonBindingImporter(Resource.fromJavaFile(file));
		var json = Streams.parse(new JsonReader(new BufferedReader(new FileReader(file))));

		Assertions.assertFalse(pmap.accept(json));
	}

	@Test
	public void testBindingImportReadEmpty() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": null}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(0, context.getPeripheralMap().size());
		Assertions.assertFalse(context.getPeripheralMap().containsKey("test"));
	}

	@Test
	public void testBindingImportReadSingle() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 123} ], \"Children\": []}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Assertions.assertEquals(1, context.getPeripheralMap().get("x").bindings.size());
		Assertions.assertEquals(123, context.getPeripheralMap().get("x").bindings.getFirst().address);
	}

	@Test
	public void testBindingImportReadMultiple() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 123} ], \"Children\": []},");
		writer.println("	{\"Name\": \"y\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 256} ], \"Children\": []},");
		writer.println("	{\"Name\": \"z\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 42} ], \"Children\": []}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(3, context.getPeripheralMap().size());
		Assertions.assertEquals(1, context.getPeripheralMap().get("x").bindings.size());
		Assertions.assertEquals(1, context.getPeripheralMap().get("y").bindings.size());
		Assertions.assertEquals(1, context.getPeripheralMap().get("y").bindings.size());
		Assertions.assertEquals(123, context.getPeripheralMap().get("x").bindings.getFirst().address);
		Assertions.assertEquals(256, context.getPeripheralMap().get("y").bindings.getFirst().address);
		Assertions.assertEquals(42, context.getPeripheralMap().get("z").bindings.getFirst().address);
	}

	@Test
	public void testBindingImportReadDuplicateNodes() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 11} ], \"Children\": []},");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 22} ], \"Children\": []},");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 33} ], \"Children\": []},");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 44} ], \"Children\": []}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Util.sameCollection(context.getPeripheralMap().get("x").bindings.stream().map(binding -> binding.address).toList(), List.of(11L, 22L, 33L, 44L));
	}

	@Test
	public void testBindingImportReadDeepNodes() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [{\"Type\": \"Bus\", \"Value\": 11}], \"Children\": [{\"Name\": \"x\", \"Bindings\": [{\"Type\": \"Bus\", \"Value\": 22}], \"Children\": []}]}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Util.sameCollection(context.getPeripheralMap().get("x").bindings.stream().map(binding -> binding.address).toList(), List.of(11L, 22L));
	}

	@Test
	public void testBindingImportReadMultipleBindings() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 11}, {\"Type\": \"Bus\", \"Value\": 22}, {\"Type\": \"Bus\", \"Value\": 33}, {\"Type\": \"Bus\", \"Value\": 44} ], \"Children\": []}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Util.sameCollection(context.getPeripheralMap().get("x").bindings.stream().map(binding -> binding.address).toList(), List.of(11L, 22L, 33L, 44L));
	}

	@Test
	public void testBindingImportIgnoreUnknown() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 123}, {\"Type\": \"Null\"}, {\"Type\": \"Unknown\"} ], \"Children\": []}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Util.sameCollection(context.getPeripheralMap().get("x").bindings.stream().map(binding -> binding.address).toList(), List.of(123L));
	}

	@Test
	public void testBindingImportIgnoreNullAlias() {
		File file = Util.createTempFile(".json");
		PrintWriter writer = Util.getFileWriter(file);

		writer.println("{\"Header\": \"Peripheral Map 1.0\", \"Root\": {\"Name\": \"Root\", \"Alias\": null, \"Bindings\": [], \"Children\": [");
		writer.println("	{\"Name\": \"x\", \"Bindings\": [ {\"Type\": \"Bus\", \"Value\": 123}, {\"Type\": \"Null\"}, {\"Type\": \"Unknown\"} ], \"Children\": []}");
		writer.println("]}}");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(file)).load(context);

		Assertions.assertEquals(1, context.getPeripheralMap().size());
		Util.sameCollection(context.getPeripheralMap().get("x").bindings.stream().map(binding -> binding.address).toList(), List.of(123L));
	}

}
