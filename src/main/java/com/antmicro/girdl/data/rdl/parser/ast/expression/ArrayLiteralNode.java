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
import com.antmicro.girdl.data.rdl.ParseUtil;
import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.List;

public class ArrayLiteralNode extends ExpressionNode {

	public final List<ExpressionNode> entries;

	public ArrayLiteralNode(Location location, List<ExpressionNode> entries) {
		super(location);
		this.entries = entries;
	}

	public static ArrayLiteralNode parse(TokenStream stream) {
		return new ArrayLiteralNode(stream.here(), ParseUtil.parseList(stream, ExpressionNode::parseExpression, ","));
	}

}
