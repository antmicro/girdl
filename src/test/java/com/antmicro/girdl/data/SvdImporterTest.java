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

import com.antmicro.girdl.data.svd.SvdField;
import com.antmicro.girdl.data.xml.XmlHelper;
import com.antmicro.girdl.model.Register;
import com.antmicro.girdl.test.Util;
import com.antmicro.girdl.util.file.Resource;
import org.apache.commons.collections.CollectionUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.PrintWriter;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class SvdImporterTest {

	@Test
	public void testSvdImportSimple() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportSimple</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Test</name>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<description>Description</description>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>A</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>B</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>C</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x20</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var registers = context.registers;

		Assertions.assertEquals(3, registers.size());
		Assertions.assertEquals("Description", registers.getFirst().binding.peripheral.getDescription());

		Assertions.assertEquals(2, registers.get(0).register.getSize());
		Assertions.assertEquals("A", registers.get(0).register.name);
		Assertions.assertEquals(0x00, registers.get(0).register.offset);
		Assertions.assertEquals(0x100, registers.get(0).getAbsoluteOffset());

		Assertions.assertEquals(2, registers.get(1).register.getSize());
		Assertions.assertEquals("B", registers.get(1).register.name);
		Assertions.assertEquals(0x10, registers.get(1).register.offset);
		Assertions.assertEquals(0x110, registers.get(1).getAbsoluteOffset());

		Assertions.assertEquals(2, registers.get(2).register.getSize());
		Assertions.assertEquals("C", registers.get(2).register.name);
		Assertions.assertEquals(0x20, registers.get(2).register.offset);
		Assertions.assertEquals(0x120, registers.get(2).getAbsoluteOffset());

	}

	@Test
	public void testSvdImportAdvanced() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportAdvanced</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<name>Name</name>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>A</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>B</name>");
		writer.println("					<description>Description</description>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var registers = context.registers;
		Assertions.assertEquals(2, registers.size());

		Assertions.assertTrue(CollectionUtils.isEqualCollection(registers.stream().map(Objects::toString).toList(), List.of(
				"Name::A at 0x100",
				"Name::B at 0x110"
		)));

		var map = context.getPeripheralMap();
		Assertions.assertTrue(map.containsKey("Name"));

		Assertions.assertEquals("", registers.get(0).register.getDescription());
		Assertions.assertEquals(2, registers.get(0).register.getSize());
		Assertions.assertEquals("A", registers.get(0).register.name);
		Assertions.assertEquals(0x00, registers.get(0).register.offset);

		Assertions.assertEquals("Description", registers.get(1).register.getDescription());
		Assertions.assertEquals(2, registers.get(1).register.getSize());
		Assertions.assertEquals("B", registers.get(1).register.name);
		Assertions.assertEquals(0x10, registers.get(1).register.offset);

	}

	@Test
	public void testSvdImportDerived() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportDerived</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral derivedFrom=\"Gpio1\">");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<name>Gpio2</name>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<baseAddress>0x000</baseAddress>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<name>Gpio1</name>");
		writer.println("			<description>Description</description>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>A</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>B</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		Util.sameCollection(context.getPeripheralMap().get("GPIO").registers.stream().map(Objects::toString).toList(), List.of(
				"A", "B"
		));
	}


	@Test
	public void testSvdImportDerivedDescription() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportDerivedDescription</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral derivedFrom=\"Gpio1\">");
		writer.println("			<name>Gpio2</name>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio1</name>");
		writer.println("			<description>Description Shared</description>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio3</name>");
		writer.println("			<description>Description Unique</description>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		Assertions.assertTrue(map.containsKey("Gpio1"));
		Assertions.assertTrue(map.containsKey("Gpio2"));
		Assertions.assertTrue(map.containsKey("Gpio3"));

		Assertions.assertEquals("Description Shared", map.get("Gpio1").getDescription());
		Assertions.assertEquals("Description Shared", map.get("Gpio2").getDescription());
		Assertions.assertEquals("Description Unique", map.get("Gpio3").getDescription());
	}

	@Test
	public void testSvdImportMergeByName() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportMergeByName</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio1</name>");
		writer.println("			<headerStructName>GPIO</headerStructName>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>A</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>B</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio2</name>");
		writer.println("			<headerStructName>GPIO</headerStructName>");
		writer.println("			<baseAddress>0x200</baseAddress>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		// the names should be merged as both peripherals share a type name and second is empty
		Assertions.assertTrue(map.containsKey("GPIO"));
		Util.sameCollection(map.get("GPIO").bindings.stream().map(bind -> bind.address).toList(), List.of(0x100L, 0x200L));
		Util.sameCollection(map.get("GPIO").bindings.stream().map(bind -> bind.name).toList(), List.of("Gpio1", "Gpio2"));
	}

	@Test
	public void testSvdImportMergeSameDefinitions() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportMergeSameDefinitions</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio1</name>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>SameA</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>SameB</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio2</name>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<baseAddress>0x200</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>SameA</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>SameB</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		Assertions.assertTrue(map.containsKey("GPIO"));
		Util.sameCollection(map.get("GPIO").bindings.stream().map(bind -> bind.address).toList(), List.of(0x100L, 0x200L));
		Util.sameCollection(map.get("GPIO").bindings.stream().map(bind -> bind.name).toList(), List.of("Gpio1", "Gpio2"));
	}

	@Test
	public void testSvdImportUseFallbackBindingName() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportUseFallbackBindingName</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio1</name>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>DifferA</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>DifferB</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio2</name>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<baseAddress>0x200</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>DifferC</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x0</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>DifferD</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		Assertions.assertTrue(map.containsKey("GPIO"));
		Assertions.assertTrue(map.containsKey("Gpio2"));

		Assertions.assertEquals(1, map.get("GPIO").bindings.size());
		Assertions.assertEquals(2, map.get("GPIO").registers.size());
		Assertions.assertEquals("DifferA", map.get("GPIO").registers.getFirst().name);

		Assertions.assertEquals(1, map.get("Gpio2").bindings.size());
		Assertions.assertEquals(2, map.get("Gpio2").registers.size());
		Assertions.assertEquals("DifferC", map.get("Gpio2").registers.getFirst().name);
	}

	@Test
	public void testSvdImportClusters() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportClusters</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio2</name>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<baseAddress>0x200</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<cluster>");
		writer.println("					<name>Favorites</name>");
		writer.println("					<register>");
		writer.println("						<name>UniqueSubA</name>");
		writer.println("						<size>0x10</size>");
		writer.println("						<addressOffset>0x10</addressOffset>");
		writer.println("					</register>");
		writer.println("					<register>");
		writer.println("						<name>UniqueSubB</name>");
		writer.println("						<size>0x10</size>");
		writer.println("						<addressOffset>0x20</addressOffset>");
		writer.println("					</register>");
		writer.println("				</cluster>");
		writer.println("				<register>");
		writer.println("					<name>UniqueSubC</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x30</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		Assertions.assertTrue(map.containsKey("GPIO"));
		List<Register> registers = map.get("GPIO").registers;

		Util.sameCollection(registers.stream().map(bind -> bind.offset).toList(), List.of(0x10L, 0x20L, 0x30L));
		Util.sameCollection(registers.stream().map(bind -> bind.name).toList(), List.of("UniqueSubA", "UniqueSubB", "UniqueSubC"));

	}

	@Test
	public void testSvdImportDerivedRegister() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportDerivedRegister</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Gpio2</name>");
		writer.println("			<groupName>GPIO</groupName>");
		writer.println("			<baseAddress>0x200</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<cluster>");
		writer.println("					<name>Favorites</name>");
		writer.println("					<register>");
		writer.println("						<name>UniqueSubA</name>");
		writer.println("						<size>0x10</size>");
		writer.println("						<addressOffset>0x10</addressOffset>");
		writer.println("					</register>");
		writer.println("					<register derivedFrom=\"UniqueSubA\">");
		writer.println("						<name>UniqueSubB</name>");
		writer.println("						<addressOffset>0x20</addressOffset>");
		writer.println("					</register>");
		writer.println("				</cluster>");
		writer.println("				<register derivedFrom=\"Gpio2.Favorites.UniqueSubA\">");
		writer.println("					<name>UniqueSubC</name>");
		writer.println("					<addressOffset>0x30</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		Assertions.assertTrue(map.containsKey("GPIO"));
		List<Register> registers = map.get("GPIO").registers;

		Util.sameCollection(registers.stream().map(Register::getSize).toList(), List.of(2, 2, 2)); // '2' not '0x10' as here we have bytes, and the value in XML is in bits
		Util.sameCollection(registers.stream().map(bind -> bind.name).toList(), List.of("UniqueSubA", "UniqueSubB", "UniqueSubC"));

	}

	@Test
	public void testSvdImportMergeMatching() {
		File svd = Util.createTempFile(".svd");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\"?>");
		writer.println("<device schemaVersion=\"1.1\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema-instance\" xs:noNamespaceSchemaLocation=\"CMSIS-SVD_Schema_1_1.xsd\">");
		writer.println("	<name>testSvdImportMergeMatching</name>");
		writer.println("	<size>0x10</size>");
		writer.println("	<peripherals>");
		writer.println("		<peripheral>");
		writer.println("			<name>Alpha</name>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>UniqueA</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>UniqueB</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x20</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Beta</name>");
		writer.println("			<groupName>Conflict</groupName>");
		writer.println("			<baseAddress>0x100</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>BetaReg</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("		<peripheral>");
		writer.println("			<name>Omega</name>");
		writer.println("			<groupName>Conflict</groupName>");
		writer.println("			<baseAddress>0x200</baseAddress>");
		writer.println("			<registers>");
		writer.println("				<register>");
		writer.println("					<name>UniqueA</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x10</addressOffset>");
		writer.println("				</register>");
		writer.println("				<register>");
		writer.println("					<name>UniqueB</name>");
		writer.println("					<size>0x10</size>");
		writer.println("					<addressOffset>0x20</addressOffset>");
		writer.println("				</register>");
		writer.println("			</registers>");
		writer.println("		</peripheral>");
		writer.println("	</peripherals>");
		writer.println("</device>");
		writer.close();

		Context context = new Context();
		Importer.of(Resource.fromJavaFile(svd)).load(context);
		context.compile();

		var map = context.getPeripheralMap();

		Assertions.assertTrue(map.containsKey("Conflict"));
		Assertions.assertTrue(map.containsKey("Alpha"));
		Assertions.assertEquals(2, map.get("Alpha").bindings.size());

		Util.sameCollection(map.get("Alpha").bindings.stream().map(Objects::toString).toList(), List.of("Alpha at 0x100", "Alpha (aka. 'Omega') at 0x200"));

	}

	@Test
	public void testFieldSizeResolutionOffsetWidth() {

		SvdField field = XmlHelper.getEmpty(SvdField.class);
		field.bitOffset = Optional.of("16");
		field.bitWidth = Optional.of("8");

		var range = field.getBitRange();
		Assertions.assertEquals(16, range.start);
		Assertions.assertEquals(8, range.size);

	}

	@Test
	public void testFieldSizeResolutionLsbMsb() {

		SvdField field = XmlHelper.getEmpty(SvdField.class);
		field.lsb = Optional.of("16");
		field.msb = Optional.of("23");

		var range = field.getBitRange();
		Assertions.assertEquals(16, range.start);
		Assertions.assertEquals(8, range.size);

	}

	@Test
	public void testFieldSizeResolutionPattern() {

		SvdField field = XmlHelper.getEmpty(SvdField.class);
		field.bitRange = Optional.of("[23:16]");

		var range = field.getBitRange();
		Assertions.assertEquals(16, range.start);
		Assertions.assertEquals(8, range.size);

	}

}
