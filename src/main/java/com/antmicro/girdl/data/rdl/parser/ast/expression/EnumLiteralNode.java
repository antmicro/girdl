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

public class EnumLiteralNode extends ExpressionNode {

	public final String type;
	public final String id;

	public EnumLiteralNode(Location location, String type, String id) {
		super(location);
		this.type = type;
		this.id = id;
	}

}
