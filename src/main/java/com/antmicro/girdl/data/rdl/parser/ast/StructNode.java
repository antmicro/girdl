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
import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.Token;
import com.antmicro.girdl.data.rdl.TokenType;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.List;

public class StructNode extends SyntaxNode {

	public final String name;
	public final String parent;
	public final boolean isAbstract;
	public final List<TypedEntryNode> entries;

	private StructNode(Location location, String name, String parent, boolean isAbstract, List<TypedEntryNode> entries) {
		super(location);
		this.name = name;
		this.parent = parent;
		this.isAbstract = isAbstract;
		this.entries = entries;
	}

	public static StructNode parse(TokenStream stream, boolean isAbstract) {
		Token identifier = stream.expect(TokenType.IDENTIFIER);
		String name = identifier.asString();
		String parent = "";

		if (stream.match(":")) {
			parent = stream.expect(TokenType.IDENTIFIER).asString();
		}

		stream.expect("{");

		TokenStream body = stream.block("{}", "struct definition");
		stream.expect(";");

		return new StructNode(identifier, name, parent, isAbstract, ParseUtil.parseList(body, TypedEntryNode::parse, ";"));
	}

}
