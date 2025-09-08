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
package com.antmicro.girdl.data.xml;

import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

class NamedLookup {

	private final Map<String, List<Node>> tags = new HashMap<>();
	private final NamedNodeMap attributes;

	private List<Node> getTag(String tag) {
		return tags.computeIfAbsent(tag, key -> new ArrayList<>());
	}

	private List<Node> getAttribute(String key) {
		return Optional.ofNullable(attributes.getNamedItem(key)).map(List::of).orElseGet(List::of);
	}

	NamedLookup(Node node) {
		attributes = node.getAttributes();

		XmlHelper.getChildStream(node).forEach(child -> {
			getTag(child.getNodeName()).add(child);
		});
	}

	List<Node> get(String name, boolean attribute) {
		return attribute ? getAttribute(name) : getTag(name);
	}

}
