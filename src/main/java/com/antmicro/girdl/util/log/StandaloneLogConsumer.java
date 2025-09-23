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

import java.io.PrintStream;

public class StandaloneLogConsumer implements LogConsumer {

	private final PrintStream stream;

	public boolean trace = true;
	public boolean info = true;
	public boolean warn = true;
	public boolean error = true;

	public StandaloneLogConsumer(PrintStream stream) {
		this.stream = stream;
	}

	private String getOriginName(Object object) {
		if (object instanceof Class<?> clazz) {
			return clazz.getSimpleName();
		}

		return object.getClass().getSimpleName();
	}

	@Override
	public void trace(Object origin, Object message) {
		if (trace) stream.println("TRACE [" + getOriginName(origin) + "]: " + message.toString());
	}

	@Override
	public void info(Object origin, Object message) {
		if (info) stream.println("INFO [" + getOriginName(origin) + "]: " + message.toString());
	}

	@Override
	public void warn(Object origin, Object message) {
		if (warn) stream.println("WARN [" + getOriginName(origin) + "]: " + message.toString());
	}

	@Override
	public void error(Object origin, Object message) {
		if (error) stream.println("ERROR [" + getOriginName(origin) + "]: " + message.toString());
	}
}
