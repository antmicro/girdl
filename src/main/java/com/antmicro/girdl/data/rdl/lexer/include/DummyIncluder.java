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
package com.antmicro.girdl.data.rdl.lexer.include;

import com.antmicro.girdl.util.file.Resource;

import java.io.IOException;
import java.util.Optional;

public class DummyIncluder implements IncludeResolver {

	private DummyIncluder() {}

	public static final IncludeResolver INSTANCE = new DummyIncluder();

	@Override
	public Resource resolve(Optional<Resource> resource, String path) throws IOException {
		throw new RuntimeException("Include resolver not set, you may not include other RDL files, if this is not desired provide a custom IncludeResolver to the RDL Tokenizer!");
	}

}
