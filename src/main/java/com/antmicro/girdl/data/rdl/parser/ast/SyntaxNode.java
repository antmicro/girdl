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
import com.antmicro.girdl.util.Reflect;
import com.antmicro.girdl.util.TreePrinter;

public abstract class SyntaxNode {

	public final Location location;

	protected SyntaxNode(Location location) {
		this.location = location;
	}

	/**
	 * Helper method, used to more easily (and unsafely) access deeply nested
	 * nodes, for example, for testing purposes.
	 */
	public final <T extends SyntaxNode> T as(Class<T> clazz) {
		if (clazz.isInstance(this)) {
			return clazz.cast(this);
		}

		throw new ClassCastException("Can't cast " + getClass().getSimpleName() + " to " + clazz.getSimpleName());
	}

	/**
	 * Debug method, prints the AST starting with this node to the
	 * standard output using box drawing characters.
	 */
	public final void dump() {
		TreePrinter printer = new TreePrinter(System.out::println, TreePrinter.BOX_DRAWING);
		Reflect.printTree(printer, SyntaxNode.class, this);
	}

	/**
	 * Debug method, return a simple combination of the simple class
	 * name and all trivially printable fields defined in that class.
	 */
	public final String toSimpleString() {
		return Reflect.getPrintInfo(SyntaxNode.class, this).getSimpleString();
	}

}
