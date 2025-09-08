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
package com.antmicro.girdl.data.rdl.parser.ast.expression;

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.ArrayList;
import java.util.List;

public class LiteralNode extends ExpressionNode {

	public final List<String> literals;

	public LiteralNode(Location location, List<String> literals) {
		super(location);
		this.literals = literals;

		if (literals.isEmpty()) {
			ParseError.create(location).setDetail("Unable to create a literal of zero length").raise();
		}
	}

	public static ExpressionNode parse(Location location, String id, TokenStream stream) {

		List<String> ids = new ArrayList<>();
		ids.add(id);

		while (stream.hasNext()) {

			if (!stream.match(".")) {
				break;
			}

			ids.add(stream.expect(TokenType.IDENTIFIER).toString());

		}

		return new LiteralNode(location, ids);

	}

	public boolean isShort() {
		return literals.size() == 1;
	}

}
