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

import com.antmicro.girdl.util.Functional;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class XmlHelper {

	private final static Node EMPTY = Functional.except(() -> DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument()).orElseThrow();

	private static boolean isElementNode(Node node) {
		return node.getNodeType() == Node.ELEMENT_NODE;
	}

	public static Stream<Node> getChildStream(Node node) {
		final NodeList list = node.getChildNodes();
		return IntStream.range(0, list.getLength()).mapToObj(list::item).filter(XmlHelper::isElementNode);
	}

	public static <T> T getEmpty(Class<T> clazz) {
		XmlParser parser = new XmlParser();
		parser.useLenientMode();
		return parser.parse(clazz, EMPTY);
	}

}
