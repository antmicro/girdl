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
package com.antmicro.girdl;

import com.antmicro.girdl.data.FilePredicate;
import com.antmicro.girdl.data.Importer;
import docking.options.editor.FileChooserEditor;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import org.apache.commons.lang3.StringUtils;

import java.io.File;

public class GirdlFileChooser extends FileChooserEditor {

	GirdlFileChooser() {
		super(new ComposedFileFilter(Importer.ALL));
	}

	@Override
	public Object getValue() {
		String text = getAsText();
		if (StringUtils.isBlank(text)) {
			return null;
		}
		return text;
	}

	public static class ComposedFileFilter implements GhidraFileFilter {

		private final FilePredicate.Combined combined;

		public ComposedFileFilter(FilePredicate.Combined combined) {
			this.combined = combined;
		}

		@Override
		public boolean accept(File pathname, GhidraFileChooserModel model) {
			return combined.accept(pathname);
		}

		@Override
		public String getDescription() {
			return combined.getDescription();
		}

	}

}
