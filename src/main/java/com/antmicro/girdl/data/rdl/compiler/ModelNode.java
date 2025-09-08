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
package com.antmicro.girdl.data.rdl.compiler;

import com.antmicro.girdl.data.rdl.Location;
import com.antmicro.girdl.util.Reflect;
import com.antmicro.girdl.util.TreePrinter;

public abstract class ModelNode {

	public transient Location location = Location.UNKNOWN;

	/**
	 * Helper method, used to more easily (and unsafely) access deeply nested
	 * nodes, for example, for testing purposes.
	 */
	public final <T extends ModelNode> T as(Class<T> clazz) {
		if (clazz.isInstance(this)) {
			return clazz.cast(this);
		}

		throw new ClassCastException("Can't cast " + getClass().getSimpleName() + " to " + clazz.getSimpleName());
	}

	/**
	 * Debug method, prints the model starting with this node to the
	 * standard output using box drawing characters. Do take into account that most of the model is
	 * created only when needed (at instantiation) so this method has to be used more strategically to see the whole tree.
	 */
	public void dump() {
		Reflect.printTree(new TreePrinter(System.out::println, TreePrinter.BOX_DRAWING), ModelNode.class, this);
	}

}
