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
import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.ArrayList;
import java.util.List;

public class PropertyReferenceNode extends SyntaxNode {

	public final List<PropertyInstanceNode> instances;

	public PropertyReferenceNode(Location location, String name) {
		this(location, List.of(new PropertyInstanceNode(location, name)));
	}

	public PropertyReferenceNode(Location location, List<PropertyInstanceNode> instances) {
		super(location);
		this.instances = instances;
	}

	public static PropertyReferenceNode parse(TokenStream stream) {

		List<PropertyInstanceNode> nodes = new ArrayList<>();
		Location location = stream.here();

		while (true) {
			nodes.add(PropertyInstanceNode.parse(stream));

			if (!stream.match(".")) {
				break;
			}
		}

		if (stream.match("->")) {
			nodes.add(PropertyInstanceNode.parse(stream));
		}

		return new PropertyReferenceNode(location, nodes);
	}

}
