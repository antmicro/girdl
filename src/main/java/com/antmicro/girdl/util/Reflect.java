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
package com.antmicro.girdl.util;

import com.antmicro.girdl.data.rdl.ParseUtil;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public final class Reflect {

	private static final int NON_SERIALIZABLE = Modifier.STATIC | Modifier.TRANSIENT;

	/**
	 * This functions copes (shallowly) optional values from one object to another.
	 * For each optional member it tries to get the values from the same optional
	 * from the other object.
	 *
	 * @param instance The object in which to "fill" optionals
	 * @param from The object from which to "read" the optionals
	 */
	public static <T> void resolveOptionals(T instance, T from) {

		if (from == null) {
			return;
		}

		if (!instance.getClass().equals(from.getClass())) {
			throw new RuntimeException("Can't assign class " + instance.getClass() + " from class " + from.getClass());
		}

		forEverySerializableField(instance.getClass(), field -> {
			if (field.getType() == Optional.class) {
				try {
					Optional<?> optional = (Optional<?>) field.get(instance);

					if (optional.isEmpty()) {
						field.set(instance, field.get(from));
					}
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}
		});
	}

	public static <T> void forEverySerializableField(Class<T> clazz, Consumer<Field> consumer) {
		forEveryField(clazz, field -> {
			if ((field.getModifiers() & NON_SERIALIZABLE) != 0) {
				return;
			}

			field.trySetAccessible();
			consumer.accept(field);
		});
	}

	public static <T> void forEveryField(Class<T> clazz, Consumer<Field> consumer) {
		Arrays.stream(clazz.getDeclaredFields()).forEach(consumer);
		Class<? super T> superClass = clazz.getSuperclass();

		if (superClass != null) {
			forEveryField(superClass, consumer);
		}
	}

	public static <T> void forEveryConstField(Class<T> clazz, Consumer<Field> consumer) {
		forEveryField(clazz, field -> {

			if ((field.getModifiers() & Modifier.TRANSIENT) != 0) {
				return;
			}

			if ((field.getModifiers() & (Modifier.STATIC | Modifier.FINAL)) != 0) {
				field.trySetAccessible();
				consumer.accept(field);
			}
		});
	}

	public static <T> T tryCreateInstance(Class<T> clazz) {
		try {
			Constructor<T> constructor = clazz.getConstructor();
			constructor.setAccessible(true);
			return constructor.newInstance();
		} catch (Exception e) {
			throw new RuntimeException("Unable to access the default constructor of class " + clazz.getName(), e);
		}
	}

	public static Object tryRead(Object object, Field field) {
		try {
			return field.get(object);
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	public static <T> PrintInfo<T> getPrintInfo(Class<T> base, T root) {

		PrintInfo<T> info = new PrintInfo<>(root);

		forEverySerializableField(root.getClass(), field -> {

			String name = field.getName();
			Object value = tryRead(root, field);

			if (value == null) {
				throw new NullPointerException("Tree node '" + root.getClass().getSimpleName() + "' has null value in field '" + name + "'");
			}

			if (base.isInstance(value)) {
				info.children.add(new Named<>(name, List.of(new Named<>("", (T) value))));
				return;
			}

			if (value.getClass().isArray()) {
				Functional.append(info.children, new Named<>(name, new ArrayList<>())).value.addAll(Arrays.stream((T[]) value).map(entry -> new Named<>("", entry)).toList());
				return;
			}

			if (field.getGenericType() instanceof ParameterizedType parameterized) {
				if (value instanceof List<?> list) {
					Class<?> clazz = (Class<?>) parameterized.getActualTypeArguments()[0];

					if (base.isAssignableFrom(clazz)) {
						Functional.append(info.children, new Named<>(name, new ArrayList<>())).value.addAll(((List<T>) list).stream().map(entry -> new Named<>("", entry)).toList());
						return;
					}
				}

				if (value instanceof Map<?, ?> map) {
					Class<?> clazz = (Class<?>) parameterized.getActualTypeArguments()[1];

					if (base.isAssignableFrom(clazz)) {
						Functional.append(info.children, new Named<>(name, new ArrayList<>())).value.addAll(((Map<Object, T>) map).entrySet().stream().map(entry -> new Named<>(entry.getKey().toString(), entry.getValue())).toList());
						return;
					}
				}

				if (value instanceof Lookup<?> lookup) {
					Class<?> clazz = (Class<?>) parameterized.getActualTypeArguments()[0];

					if (base.isAssignableFrom(clazz)) {
						Functional.append(info.children, new Named<>(name, new ArrayList<>())).value.addAll(((Lookup<T>) lookup).entries().entrySet().stream().map(entry -> new Named<>(entry.getKey(), entry.getValue())).toList());
						return;
					}
				}
			}

			info.members.add(new Named<>(name, value));

		});

		return info;

	}

	public static <T> void printTree(TreePrinter printer, Class<T> base, T root) {
		printTree(printer, base, root, "", new HashSet<>());
	}

	private static <T> void printTree(TreePrinter printer, Class<T> base, T root, String prefix, Set<Object> printed) {

		if (printed.contains(root)) {
			printer.println(0, "[Loop: " + root.toString() + "]");
			return;
		}

		printed.add(root);

		final PrintInfo<T> info = getPrintInfo(base, root);
		printer.println(info.children.size(), (prefix.isEmpty() ? "" : prefix + ": ") + info.getSimpleString());

		info.children.forEach(child -> {
			printer.println(child.value.size(),  "#" + child.name);

			child.value.forEach(entry -> {
				try {
					printTree(printer, base, entry.value, entry.name, new HashSet<>(printed));
				} catch (Exception e) {
					throw new RuntimeException("Exception while printing field '" + child.name + "' of class '" + root.getClass().getSimpleName() + "'", e);
				}
			});
		});
	}

	public static <T> String constValueName(Class<T> clazz, int value) {
		Mutable<String> str = Mutable.wrap(null);

		forEveryConstField(clazz, field -> {
			if (tryRead(clazz, field) instanceof Integer i) {
				if (value == i) str.value = field.getName();
			}
		});

		return str.value;
	}

	public static <T> String constFlagName(Class<T> clazz, int value) {
		List<String> flags = new ArrayList<>();

		forEveryConstField(clazz, field -> {
			if (tryRead(clazz, field) instanceof Integer i) {
				if ((value & i) != 0) flags.add(field.getName());
			}
		});

		return String.join(" | ", flags);
	}

	public static class PrintInfo<T> {
		final Object root;
		final List<Named<Object>> members = new ArrayList<>();
		final List<Named<List<Named<T>>>> children = new ArrayList<>();

		public PrintInfo(Object root) {
			this.root = root;
		}

		public String getSimpleString() {
			return root.getClass().getSimpleName() + " " + members.stream().map(Object::toString).collect(Collectors.joining(", "));
		}
	}

	private record Named<T>(String name, T value) {

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder(name).append("=");

			if (value instanceof String literal) {
				builder.append(ParseUtil.quote(literal));
			} else {
				builder.append(value);
			}

			return builder.toString();
		}
	}

}
