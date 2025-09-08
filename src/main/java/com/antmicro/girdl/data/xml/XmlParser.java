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

import com.antmicro.girdl.util.Reflect;
import org.w3c.dom.Node;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public class XmlParser {

	private boolean lenient = false;

	/**
	 * In lenient mode the parser will fill missing required fields with nulls.
	 */
	public XmlParser useLenientMode() {
		this.lenient = true;
		return this;
	}

	@SuppressWarnings("unchecked")
	public <T> T parse(Class<T> clazz, Node node) {
		return (T) parseNode(null, clazz, node);
	}

	private <T> Object parseNode(Object parent, Class<T> clazz, Node node) {

		if (clazz == String.class) {
			return node.getTextContent();
		}

		if (clazz == Long.class) {
			return Long.decode(node.getTextContent());
		}

		if (clazz == Integer.class) {
			return Integer.decode(node.getTextContent());
		}

		if (clazz == Short.class) {
			return Short.decode(node.getTextContent());
		}

		if (clazz == Byte.class) {
			return Byte.decode(node.getTextContent());
		}

		if (clazz == Boolean.class) {
			return Boolean.parseBoolean(node.getTextContent());
		}

		NamedLookup lookup = new NamedLookup(node);
		T instance = Reflect.tryCreateInstance(clazz);

		Reflect.forEverySerializableField(clazz, field -> {
			String name = field.getName();
			Class<?> child = field.getType();
			Object result;

			if (hasAttribute(field, XmlParent.class)) {

				if (!field.getType().isAssignableFrom(parent.getClass())) {
					throw new RuntimeException("A reference to the parent class " + parent.getClass().getName() + " can't be written to '" + field.getName() + "' of type " + field.getType().getName() + " in class " + clazz.getTypeName());
				}

				result = parent;
			} else {
				List<Node> nodes = lookup.get(name, hasAttribute(field, XmlAttribute.class));

				if (field.getGenericType() instanceof ParameterizedType parameterized) {

					Class<?> base = (Class<?>) parameterized.getRawType();
					Class<?> generic = (Class<?>) parameterized.getActualTypeArguments()[0];

					if (base == List.class) {
						result = nodes.stream().map(n -> parseNode(instance, generic, n)).toList();
					} else if (base == Optional.class) {
						result = nodes.stream().map(n -> parseNode(instance, generic, n)).findAny();
					} else {
						throw new RuntimeException("Unknown generic type " + base.getTypeName() + " in class " + clazz.getTypeName());
					}

				} else {
					result = extractRequired(nodes.stream().map(n -> parseNode(instance, field.getType(), n)).findAny(), () ->
							new MissingFieldException(name, child, clazz)
					);
				}
			}

			try {
				field.set(instance, result);
			} catch (Exception e) {
				throw new RuntimeException("Unable to set field '" + name + "' in class " + clazz.getTypeName());
			}
		});

		return instance;

	}

	private <X extends Throwable> Object extractRequired(Optional<Object> wrapped, Supplier<X> supplier) throws X {
		return lenient ? wrapped.orElse(null) : wrapped.orElseThrow(supplier);
	}

	public static XmlParser create() {
		return new XmlParser();
	}

	private <T extends Annotation> boolean hasAttribute(Field field, Class<T> annotation) {
		return field.getAnnotation(annotation) != null;
	}

}
