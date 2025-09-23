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
package com.antmicro.girdl.test;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.SystemUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.stream.Collectors;

public final class Util {

	public static File createTempFile(String suffix) {
		return createTempFile("renode-test-", suffix);
	}

	public static File createTempFile(String prefix, String suffix) {
		try {
			File file = File.createTempFile(prefix, "-renode-test" + suffix);
			file.deleteOnExit();

			return file;
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static PrintWriter getFileWriter(File file) {
		try {
			return new PrintWriter(file, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static <T> void sameCollection(Collection<T> left, Collection<T> right) {
		Assertions.assertTrue(CollectionUtils.isEqualCollection(left, right));
	}

	public static void skipIfNoI3cCore(Object object) {

		// it's not really critical so if the i3c-core hasn't been cloned just skip the test
		Assumptions.assumeTrue(object.getClass().getResource("/i3c/LICENSE") != null, "I3C-core not available, to enable this test run 'git submodule update --init --recursive'");
	}

	public static String getCommandOutput(String... args) {

		Assumptions.assumeTrue(SystemUtils.IS_OS_UNIX, "This test require an UNIX compatible OS");

		try {
			Process process = Runtime.getRuntime().exec(args);
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			Assertions.assertEquals(0, process.waitFor());

			return reader.lines().collect(Collectors.joining());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
