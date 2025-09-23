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
package com.antmicro.girdl.data;

import com.antmicro.girdl.util.file.Resource;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public final class FilePredicate implements Predicate<Resource> {

	private final Predicate<Resource> predicate;
	private final ImporterConstructor constructor;
	private final String description;

	FilePredicate(Predicate<Resource> predicate, ImporterConstructor constructor, String description) {
		this.predicate = predicate;
		this.constructor = constructor;
		this.description = description;
	}

	public ImporterConstructor getConstructor() {
		return constructor;
	}

	public FilePredicate withoutDescription() {
		return new FilePredicate(predicate, constructor, null);
	}

	@Override
	public String toString() {
		return description;
	}

	@Override
	public boolean test(Resource file) {
		return predicate.test(file);
	}

	public static FilePredicate byExtension(ImporterConstructor constructor, String... extensions) {
		return new FilePredicate(file -> file.isFile() && Arrays.stream(extensions).anyMatch(file::endsWith), constructor, combineParts(List.of(extensions)));
	}

	public static Combined combined(FilePredicate... predicates) {
		return new Combined(List.of(predicates));
	}

	public interface ImporterConstructor {
		Importer get(Resource file) throws Exception;
	}

	static <T> String combineParts(List<T> objects) {
		return objects.stream().map(Objects::toString).filter(Objects::nonNull).collect(Collectors.joining(", "));
	}

	public final static class Combined {

		private final List<FilePredicate> predicates;

		public Combined(List<FilePredicate> predicates) {
			this.predicates = predicates;
		}

		Optional<ImporterConstructor> getMatching(Resource file) {
			return predicates.stream().filter(predicate -> predicate.test(file)).map(FilePredicate::getConstructor).findFirst();
		}

		public boolean accept(File pathname) {
			final Resource resource = Resource.fromJavaFile(pathname);
			return predicates.stream().anyMatch(predicate -> predicate.test(resource));
		}

		public String getDescription() {
			return combineParts(predicates);
		}

	}

}
