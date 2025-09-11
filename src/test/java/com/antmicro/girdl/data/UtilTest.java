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

import com.antmicro.girdl.data.elf.enums.ElfMachine;
import com.antmicro.girdl.data.elf.enums.ElfSectionFlag;
import com.antmicro.girdl.util.DataSource;
import com.antmicro.girdl.util.Functional;
import com.antmicro.girdl.util.IndexedIterator;
import com.antmicro.girdl.util.MathHelper;
import com.antmicro.girdl.util.Mutable;
import com.antmicro.girdl.util.Reflect;
import com.antmicro.girdl.util.TreePrinter;
import com.antmicro.girdl.util.file.Resource;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

public class UtilTest {

	@Test
	void testFunctionalCartisian() {
		List<Pair<Integer, String>> result = Functional.cartesian(List.of(1, 2, 3), List.of("a", "b")).toList();

		List<Pair<Integer, String>> expected = List.of(
				Pair.of(1, "a"),
				Pair.of(1, "b"),
				Pair.of(2, "a"),
				Pair.of(2, "b"),
				Pair.of(3, "a"),
				Pair.of(3, "b")
		);

		Assertions.assertEquals(expected, result);
	}

	@Test
	void testFunctionalFold() {
		String result = Functional.fold(IntStream.range(0, 10).boxed(), "#", (value, element) -> value + element);

		Assertions.assertEquals("#0123456789", result);
	}

	@Test
	void testIndexedIterator() {
		List<String> strings = new ArrayList<>();

		strings.add("100");
		strings.add("101");
		strings.add("102");

		int count = 0;

		for (var entry : IndexedIterator.of(strings)) {
			Assertions.assertEquals(String.valueOf(entry.index() + 100), entry.value());
			count ++;
		}

		Assertions.assertEquals(3, count);
	}

	@Test
	void testMutableHolder() {
		Mutable<Integer> mutable = Mutable.wrap(100);
		mutable.map(value -> value * 10);

		Assertions.assertEquals(1000, mutable.value);
	}

	@Test
	public void testResourceAccess() throws IOException {
		Resource file = Resource.fromJavaResource(this, "/test.txt");

		Assertions.assertNotNull(file);
		String content = new String(file.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

		Assertions.assertTrue(file.isFile());
		Assertions.assertEquals("Lorem ipsum", content);
	}

	@Test
	public void testTreePrinter() {

		TreePrinter printer = new TreePrinter();

		Assertions.assertEquals("", printer.enter(3));
		Assertions.assertEquals("+- ", printer.enter(2));
		Assertions.assertEquals("|  +- ", printer.enter(0));
		Assertions.assertEquals("|  '- ", printer.enter(0));
		Assertions.assertEquals("+- ", printer.enter(1));
		Assertions.assertEquals("|  '- ", printer.enter(0));
		Assertions.assertEquals("'- ", printer.enter(1));
		Assertions.assertEquals("   '- ", printer.enter(0));

	}

	@Test
	public void testMathAlignUp() {

		Assertions.assertEquals(16, MathHelper.alignUp(11, 8));
		Assertions.assertEquals(64, MathHelper.alignUp(63, 64));
		Assertions.assertEquals(128, MathHelper.alignUp(65, 64));
		Assertions.assertEquals(13, MathHelper.alignUp(13, 1));
		Assertions.assertEquals(13, MathHelper.alignUp(13, 0));

	}

	@Test
	public void testDataSource() {

		DataSource source = new DataSource();
		source.addSource("");
		source.addSource("First");
		source.addSource("Second");
		source.addSource("");
		source.addSource(null);
		source.addSource("Third");

		Assertions.assertEquals("First", source.primary().get());

		List<String> list = new ArrayList<>();
		source.forEachNonPrimary(list::add);

		Assertions.assertEquals(2, list.size());
		Assertions.assertEquals("Second", list.get(0));
		Assertions.assertEquals("Third", list.get(1));

	}

	@Test
	public void testDataSourceWithDuplicate() {

		DataSource source = new DataSource();
		source.addSource("First");
		source.addSource("First");
		source.addSource("Second");

		Assertions.assertTrue(source.primary().isPresent());
		Assertions.assertEquals("First", source.primary().get());

		List<String> list = new ArrayList<>();
		source.forEachNonPrimary(list::add);

		Assertions.assertEquals(1, list.size());
		Assertions.assertEquals("Second", list.getFirst());

	}

	@Test
	public void testReflectConstNames() {

		Assertions.assertNull(Reflect.constValueName(ElfMachine.class, -1));

		// const name
		Assertions.assertEquals("RISCV", Reflect.constValueName(ElfMachine.class, ElfMachine.RISCV));
		Assertions.assertEquals("X86_64", Reflect.constValueName(ElfMachine.class, ElfMachine.X86_64));

		// flag name
		Assertions.assertEquals("ALLOC", Reflect.constFlagName(ElfSectionFlag.class, ElfSectionFlag.ALLOC));
		Assertions.assertEquals("MERGE | STRINGS", Reflect.constFlagName(ElfSectionFlag.class, ElfSectionFlag.MERGE | ElfSectionFlag.STRINGS));

	}

}
