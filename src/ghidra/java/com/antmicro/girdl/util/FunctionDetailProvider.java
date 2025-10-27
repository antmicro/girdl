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

import com.antmicro.girdl.model.type.FunctionNode;
import ghidra.program.model.listing.Function;

import java.util.List;
import java.util.Optional;

@FunctionalInterface
public interface FunctionDetailProvider {

	/**
	 * Get certain information about the functions, that
	 * can only be obtained by performing a decompilation.
	 */
	Optional<FunctionInfo> getFunctionDetails(Function ghidraFunction);

	class FunctionInfo {
		public final List<FunctionNode.Variable> locals;

		public FunctionInfo(List<FunctionNode.Variable> locals) {
			this.locals = locals;
		}
	}

}
