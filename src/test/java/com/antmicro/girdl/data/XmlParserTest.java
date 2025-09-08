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

import com.antmicro.girdl.data.xml.MissingFieldException;
import com.antmicro.girdl.data.xml.XmlAttribute;
import com.antmicro.girdl.data.xml.XmlParent;
import com.antmicro.girdl.data.xml.XmlParser;
import com.antmicro.girdl.test.Util;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.PrintWriter;
import java.util.List;
import java.util.Optional;

public class XmlParserTest {

	public static class SchemaSimpleRequired {
		String string;
		Long longNumber;
		Integer intNumber;
		Short shortNumber;
		Byte byteNumber;
		Boolean bool;
	}

	@Test
	public void testSimpleRequired() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("	<longNumber>123456</longNumber>");
		writer.println("	<intNumber>12345</intNumber>");
		writer.println("	<shortNumber>1234</shortNumber>");
		writer.println("	<byteNumber>123</byteNumber>");
		writer.println("	<bool>true</bool>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaSimpleRequired.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Lorem Ipsum", instance.string);
		Assertions.assertEquals(123456, instance.longNumber);
		Assertions.assertEquals(12345, instance.intNumber);
		Assertions.assertEquals((short) 1234, instance.shortNumber);
		Assertions.assertEquals((byte) 123, instance.byteNumber);
		Assertions.assertEquals(true, instance.bool);
	}

	@Test
	public void testSimpleRequiredMissing() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("	<longNumber>123456</longNumber>");
		writer.println("	<intNumber>12345</intNumber>");
		writer.println("	<shortNumber>1234</shortNumber>");
		writer.println("	<bool>true</bool>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		MissingFieldException e = Assertions.assertThrows(MissingFieldException.class, () -> {
			XmlParser.create().parse(SchemaSimpleRequired.class, document.getElementsByTagName("root").item(0));
		});

		Assertions.assertEquals("byteNumber", e.name);
		Assertions.assertEquals(SchemaSimpleRequired.class, e.clazz);
		Assertions.assertEquals(Byte.class, e.field);
	}

	@Test
	public void testSimpleRequiredDuplicate() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("	<longNumber>123456</longNumber>");
		writer.println("	<intNumber>12345</intNumber>");
		writer.println("	<shortNumber>1234</shortNumber>");
		writer.println("	<byteNumber>123</byteNumber>");
		writer.println("	<byteNumber>12</byteNumber>");
		writer.println("	<byteNumber>1</byteNumber>");
		writer.println("	<bool>true</bool>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaSimpleRequired.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Lorem Ipsum", instance.string);

		// if we expect a single tag but got multiple, one should be chosen at random
		byte value = instance.byteNumber;
		Assertions.assertTrue(value == 1 || value == 12 || value == 123);
	}

	public static class SchemaOptionalField {
		String string;
		Optional<String> optional;
	}

	@Test
	public void testOptionalFieldPresent() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("	<optional>Optional String</optional>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaOptionalField.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Lorem Ipsum", instance.string);
		Assertions.assertEquals("Optional String", instance.optional.orElseThrow());
	}

	@Test
	public void testOptionalFieldMissing() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaOptionalField.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Lorem Ipsum", instance.string);
		Assertions.assertTrue(instance.optional.isEmpty());
	}

	@Test
	public void testOptionalFieldDuplicate() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("	<optional>A1</optional>");
		writer.println("	<optional>A2</optional>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaOptionalField.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Lorem Ipsum", instance.string);
		Assertions.assertTrue(instance.optional.isPresent());

		// if we expect a single tag but got multiple one should be chosen at random
		String value = instance.optional.orElseThrow();
		Assertions.assertTrue(value.equals("A1") || value.equals("A2"));
	}

	public static class SchemaListField {
		String string;
		Optional<Long> numeric;
		List<String> entry;
	}

	@Test
	public void testListField() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Lorem Ipsum</string>");
		writer.println("	<numeric>123</numeric>");
		writer.println("	<entry>A1</entry>");
		writer.println("	<entry>A2</entry>");
		writer.println("	<entry>A3</entry>");
		writer.println("	<entry>A4</entry>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaListField.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Lorem Ipsum", instance.string);
		Assertions.assertEquals(123L, instance.numeric.orElseThrow());
		Util.sameCollection(instance.entry, List.of("A1", "A2", "A3", "A4"));
	}

	public static class SchemaRecursive {
		String string;
		Optional<SchemaDetails> detail;
		List<SchemaRecursive> entry;
	}

	public static class SchemaDetails {
		String description;
		Integer value;
	}

	@Test
	public void testRecursive() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root>");
		writer.println("	<string>Outer</string>");
		writer.println("	<detail>");
		writer.println("		<description>The Answer</description>");
		writer.println("		<value>42</value>");
		writer.println("	</detail>");
		writer.println("	<entry>");
		writer.println("		<string>Inner 1</string>");
		writer.println("		<detail>");
		writer.println("			<description>Days in a week</description>");
		writer.println("			<value>7</value>");
		writer.println("		</detail>");
		writer.println("	</entry>");
		writer.println("	<entry>");
		writer.println("		<string>Inner 2</string>");
		writer.println("	</entry>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaRecursive.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Outer", instance.string);
		Assertions.assertEquals(2, instance.entry.size());
		Assertions.assertTrue(instance.detail.isPresent());

		Assertions.assertEquals("The Answer", instance.detail.orElseThrow().description);
		Assertions.assertEquals(42, instance.detail.orElseThrow().value);
		Util.sameCollection(instance.entry.stream().map(s -> s.string).toList(), List.of("Inner 1", "Inner 2"));

	}

	public static class SchemaAttributes {
		String string;

		@XmlAttribute
		String attr1;

		@XmlAttribute
		Integer attr2;
	}

	@Test
	public void testAttributes() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root attr1=\"Lorem Ipsum\" attr2=\"123\">");
		writer.println("	<string>Hello</string>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaAttributes.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("Hello", instance.string);
		Assertions.assertEquals("Lorem Ipsum", instance.attr1);
		Assertions.assertEquals(123, instance.attr2);
	}

	public static class SchemaAttributesOptional {
		@XmlAttribute
		Optional<String> value;
	}

	@Test
	public void testAttributesOptionalPresent() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root value=\"Present\"></root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaAttributesOptional.class, document.getElementsByTagName("root").item(0));
		Assertions.assertEquals("Present", instance.value.orElseThrow());
	}

	@Test
	public void testAttributesOptionalMissing() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root></root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaAttributesOptional.class, document.getElementsByTagName("root").item(0));
		Assertions.assertTrue(instance.value.isEmpty());
	}

	public static class SchemaBase {
		String base;
	}

	public static class SchemaDerived extends SchemaBase {
		String derived;
	}

	@Test
	public void testInheritance() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root unused=\"some value\">");
		writer.println("	<base>base</base>");
		writer.println("	<derived>derived</derived>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaDerived.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("base", instance.base);
		Assertions.assertEquals("derived", instance.derived);
	}

	public static class SchemaTransience {
		String string;
		transient Long value;
	}

	@Test
	public void testTransience() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root unused=\"some value\">");
		writer.println("	<string>string</string>");
		writer.println("	<value>123</value>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaTransience.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals("string", instance.string);
		Assertions.assertNull(instance.value);
	}

	public static class SchemaGoodParental {
		SchemaGoodChild child;
	}

	public static class SchemaGoodChild {
		@XmlParent
		SchemaGoodParental parent;

		@XmlParent
		Object object;
	}

	@Test
	public void testGoodParental() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root unused=\"some value\">");
		writer.println("	<child></child>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		var instance = XmlParser.create().parse(SchemaGoodParental.class, document.getElementsByTagName("root").item(0));

		Assertions.assertEquals(instance, instance.child.parent);
		Assertions.assertEquals(instance, instance.child.object);
	}

	public static class SchemaBadParental {
		SchemaBadChild child;
	}

	public static class SchemaBadChild {
		@XmlParent
		SchemaGoodParental parent;
	}

	@Test
	public void testBadParental() throws Exception {
		File svd = Util.createTempFile(".xml");
		PrintWriter writer = Util.getFileWriter(svd);

		writer.println("<root unused=\"some value\">");
		writer.println("	<child></child>");
		writer.println("</root>");
		writer.close();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setIgnoringElementContentWhitespace(true);
		var document = factory.newDocumentBuilder().parse(svd);

		Assertions.assertThrows(RuntimeException.class, () -> {
			XmlParser.create().parse(SchemaBadParental.class, document.getElementsByTagName("root").item(0));
		});
	}

}

