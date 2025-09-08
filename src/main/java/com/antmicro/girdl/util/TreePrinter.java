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

import java.util.Stack;
import java.util.function.Consumer;

public final class TreePrinter {

	public static final Bark ASCII = new Bark("+- ", "'- ", "|  ", "   ");
	public static final Bark BOX_DRAWING = new Bark("┣━ ", "┗━ ", "┃  ", "   ");

	private final Consumer<String> backend;
	private final Stack<Level> levels = new Stack<>();
	private final Bark bark;

	public TreePrinter(Consumer<String> backend, Bark bark) {
		this.backend = backend;
		this.bark = bark;
	}

	public TreePrinter() {
		this(System.out::println, ASCII);
	}

	public void println(int children, String message) {
		backend.accept(enter(children) + message);
	}

	public String enter(int children) {
		String self = toString();
		push(children);
		return self;
	}

	public void push(int children) {

		if (!levels.isEmpty()) {
			levels.getLast().index ++;
		}

		if (children != 0) {
			levels.push(new Level(children));
			return;
		}

		while (!levels.isEmpty() && levels.getLast().shouldPop()) {
			levels.pop();
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();

		int last = levels.size() - 1;

		for (int i = 0; i < levels.size(); i ++) {
			Level level = levels.get(i);

			builder.append(bark.get(!level.isLast(), last == i, level.shouldPop()));
		}

		return builder.toString();
	}

	private static final class Level {

		int count;
		int index;

		private Level(int count) {
			this.count = count;
			this.index = 1;
		}

		private boolean isLast() {
			return index >= count;
		}

		private boolean shouldPop() {
			return index > count;
		}

	}

	public static final class Bark {

		private final String blank;
		private final String[][] matrix;

		private Bark(String neighbour, String last, String alone, String blank) {
			this.blank = blank;
			this.matrix = new String[][] {
					{alone, last},
					{alone, neighbour},
			};
		}

		private String get(boolean nonLast, boolean neighbour, boolean ignore) {
			return ignore ? blank : matrix[nonLast ? 1 : 0][neighbour ? 1 : 0];
		}

	}

}
