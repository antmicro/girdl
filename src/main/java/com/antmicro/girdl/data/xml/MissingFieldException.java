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

public class MissingFieldException extends RuntimeException {

	public final String name;
	public final Class<?> field;
	public final Class<?> clazz;

	public MissingFieldException(String name, Class<?> field, Class<?> clazz) {
		this.name = name;
		this.field = field;
		this.clazz = clazz;
	}

	@Override
	public String getMessage() {
		return "Required field '" + name + "' of type " + field.getTypeName() + " in class " + clazz.getTypeName() + " was missing";
	}

}
