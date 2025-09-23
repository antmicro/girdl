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
package com.antmicro.girdl.util.log;

public class Logger {

	private static LogConsumer consumer = new StandaloneLogConsumer(System.out);

	public static void setSink(LogConsumer consumer) {
		Logger.consumer = consumer;
	}

	public static void trace(Object origin, Object message) {
		consumer.trace(origin, message);
	}

	public static void info(Object origin, Object message) {
		consumer.info(origin, message);
	}

	public static void warn(Object origin, Object message) {
		consumer.warn(origin, message);
	}

	public static void error(Object origin, Object message) {
		consumer.error(origin, message);
	}

}
