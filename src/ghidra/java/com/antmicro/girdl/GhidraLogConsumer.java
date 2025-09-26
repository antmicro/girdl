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

import com.antmicro.girdl.util.log.LogConsumer;
import ghidra.util.Msg;

public class GhidraLogConsumer implements LogConsumer {

	@Override
	public void trace(Object origin, Object message) {
		Msg.trace(origin, message);
	}

	@Override
	public void debug(Object origin, Object message) {
		Msg.debug(origin, message);
	}

	@Override
	public void info(Object origin, Object message) {
		Msg.info(origin, message);
	}

	@Override
	public void warn(Object origin, Object message) {
		Msg.warn(origin, message);
	}

	@Override
	public void error(Object origin, Object message) {
		Msg.error(origin, message);
	}

}
