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
package com.antmicro.girdl.data.svd;

import com.antmicro.girdl.data.xml.XmlAttribute;

import java.util.Optional;

public class SvdRegister implements SvdNamed {
	public String name;

	@XmlAttribute
	public Optional<String> derivedFrom;

	public Optional<Long> addressOffset;
	public Optional<String> description;
	public Optional<Long> size;
	public Optional<SvdFields> fields;

	@Override
	public String getName() {
		return name;
	}
}
