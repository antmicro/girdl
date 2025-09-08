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
package com.antmicro.girdl.data.rdl;

import com.antmicro.girdl.data.rdl.parser.TokenStream;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class ParseUtil {

	public static <T> List<T> parseList(TokenStream stream, Function<TokenStream, T> parser, String delimiter)  {
		List<T> nodes = new ArrayList<>();

		while (stream.hasNext()) {
			nodes.add(parser.apply(stream));

			// allow omitting delimiter at the end
			if (stream.isEmpty()) {
				break;
			}

			stream.expect(delimiter);
		}

		return nodes;
	}

	public static String quote(String value) {
		return "\"" + value + "\"";
	}

	public static String quote(char value) {
		return "'" + value + "'";
	}

	public static boolean isDecimalDigit(char c) {
		return c >= '0' && c <= '9';
	}

	public static boolean isHexadecimalDigit(char c) {
		return isDecimalDigit(c) || (c >= 'A' && c <= 'F') ||  (c >= 'a' && c <= 'f');
	}

	public static boolean isLetterOrUnderscore(char c) {
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '_');
	}

	public static boolean isLetterOrDigit(char c) {
		return isLetterOrUnderscore(c) || isDecimalDigit(c);
	}

}
