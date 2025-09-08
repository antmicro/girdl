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
package com.antmicro.girdl.data.rdl.parser;

import com.antmicro.girdl.data.rdl.Token;

import java.util.List;

public class PaddedTokenStream extends TokenStream {

	public PaddedTokenStream(List<Token> tokens, int start, int end, String name) {
		super(tokens, start, end, name);
	}

	public TokenStream trim() {
		return new TokenStream(tokens, start, end - 1, Math.min(index, end - 2), name);
	}

}
