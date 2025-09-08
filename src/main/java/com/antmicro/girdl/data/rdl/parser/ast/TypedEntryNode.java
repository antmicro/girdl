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
package com.antmicro.girdl.data.rdl.parser.ast;

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

public class TypedEntryNode extends SyntaxNode {

	public final String type;
	public final String name;
	public final boolean isArray;

	public TypedEntryNode(Location location, String type, String name, boolean isArray) {
		super(location);
		this.type = type;
		this.name = name;
		this.isArray = isArray;
	}

	public static TypedEntryNode parse(TokenStream stream) {

		boolean isArray = false;

		Token identifier = stream.expect(TokenType.IDENTIFIER);
		String type = identifier.asString();

		if (stream.match("unsigned")) {
			type = "unsigned " + type;
		}

		String name = stream.expect(TokenType.IDENTIFIER).asString();

		if (stream.match("[")) {
			stream.expect("]");
			isArray = true;
		}

		return new TypedEntryNode(identifier, type, name, isArray);

	}

}
