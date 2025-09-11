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
package com.antmicro.girdl.model.type;

import com.antmicro.girdl.util.Reflect;
import com.antmicro.girdl.util.TreePrinter;

public abstract class TypeNode {

	public final void dump() {
		TreePrinter printer = new TreePrinter(System.out::println, TreePrinter.BOX_DRAWING);
		Reflect.printTree(printer, TypeNode.class, this);
	}

	public abstract <T> T adapt(Adapter<T> adapter);
	public abstract int size();

}
