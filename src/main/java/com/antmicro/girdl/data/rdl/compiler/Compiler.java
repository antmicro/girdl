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
import com.antmicro.girdl.data.rdl.ParseError;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentType;
import com.antmicro.girdl.data.rdl.compiler.model.ComponentValue;
import com.antmicro.girdl.data.rdl.compiler.model.EnumType;
import com.antmicro.girdl.data.rdl.compiler.model.ParametricType;
import com.antmicro.girdl.data.rdl.compiler.model.PrimitiveType;
import com.antmicro.girdl.data.rdl.compiler.model.PrimitiveValue;
import com.antmicro.girdl.data.rdl.compiler.model.StructType;
import com.antmicro.girdl.data.rdl.compiler.model.StructuredValue;
import com.antmicro.girdl.data.rdl.compiler.model.SymbolicType;
import com.antmicro.girdl.data.rdl.compiler.model.TypeValue;
import com.antmicro.girdl.data.rdl.compiler.model.UnsetValue;
import com.antmicro.girdl.data.rdl.compiler.model.Value;
import com.antmicro.girdl.data.rdl.parser.ComponentKind;
import com.antmicro.girdl.data.rdl.parser.ast.ComponentDefinitionNode;
import com.antmicro.girdl.data.rdl.parser.ast.ComponentInstanceNode;
import com.antmicro.girdl.data.rdl.parser.ast.ComponentNode;
import com.antmicro.girdl.data.rdl.parser.ast.EnumEntryNode;
import com.antmicro.girdl.data.rdl.parser.ast.EnumNode;
import com.antmicro.girdl.data.rdl.parser.ast.ExplicitInstantiationNode;
import com.antmicro.girdl.data.rdl.parser.ast.InstantiationNode;
import com.antmicro.girdl.data.rdl.parser.ast.PropertyAssignmentNode;
import com.antmicro.girdl.data.rdl.parser.ast.RangeInstantiationNode;
import com.antmicro.girdl.data.rdl.parser.ast.RootNode;
import com.antmicro.girdl.data.rdl.parser.ast.StructNode;
import com.antmicro.girdl.data.rdl.parser.ast.SyntaxNode;
import com.antmicro.girdl.data.rdl.parser.ast.TypedEntryNode;
import com.antmicro.girdl.data.rdl.parser.ast.ValuedEntryNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.ArrayLiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.BinaryExpression;
import com.antmicro.girdl.data.rdl.parser.ast.expression.BoolNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.EnumLiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.ExpressionNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.IntegerNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.LiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.StringNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.StructLiteralNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.TernaryOperatorNode;
import com.antmicro.girdl.data.rdl.parser.ast.expression.UnaryExpression;
import com.antmicro.girdl.util.UnimplementedException;
import com.antmicro.girdl.util.log.Logger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

/**
 * The compiler is responsible for taking the raw AST and converting it into a model,
 * that is - a definitive static view of the document with resolved types and expressions.
 */
public class Compiler {

	private final ComponentType top = new ComponentType("top", ComponentKind.TOP, StructuredValue.empty());
	private final Map<String, TypeValue> types = new HashMap<>();

	private TypeValue registerType(TypeValue type) {
		if (!type.name.isEmpty()) {
			types.put(type.name, type);
		}

		return type;
	}

	/**
	 * Currently this method does pretty much nothing, we should probably either remove linkType() or findType().
	 * In the past type information was allowed to be resolved later but after some changes now the type needs to be defined
	 * before it is used, if this is fine by RDL spec remove this, otherwise lever it be until we figure out how to restore
	 * the old functionality.
	 */
	private void linkType(Location location, String name, Consumer<TypeValue> callback) {
		callback.accept(findType(location, name));
	}

	private StructuredValue compileStructLiteral(Scope scope, StructLiteralNode node) {
		StructuredValue value = new StructuredValue(StructType.ANONYMOUS);
		value.location = node.location;

		for (StructLiteralNode.EntryNode entry : node.entries) {
			value.values.put(entry.name, compileValue(scope, entry.value));
		}

		return value;
	}

	private Value compileValue(Scope scope, ExpressionNode node) {

		if (node instanceof IntegerNode that) {
			return PrimitiveValue.IntValue.of(that.value).setLocation(that.location);
		}

		if (node instanceof StringNode that) {
			return PrimitiveValue.TextValue.of(that.value).setLocation(that.location);
		}

		if (node instanceof BoolNode that) {
			return PrimitiveValue.BoolValue.of(that.value).setLocation(that.location);
		}

		if (node instanceof EnumLiteralNode that) {
			return PrimitiveValue.IntValue.of(((EnumType) findType(that.location, that.type)).getEnumerationByName(that.id).toLong()).setLocation(that.location);
		}

		if (node instanceof LiteralNode that) {
			if (that.isShort()) {
				Value value = SymbolicType.parseOrNull(that.literals.getFirst());

				if (value != null) {
					value.location = that.location;
					return value;
				}
			} else {
				throw UnimplementedException.ofPlural("multi-literals");
			}

			// TODO multi-literals
			Logger.trace(this, "The literal node '" + that.literals.getFirst() + "' will be treated as a variable reference!");
			return scope.get(that.location, that.literals.getFirst());
		}

		if (node instanceof BinaryExpression that) {
			return that.type.apply(compileValue(scope, that.left), compileValue(scope, that.right)).setLocation(that.location);
		}

		if (node instanceof UnaryExpression that) {
			return that.type.apply(compileValue(scope, that.node)).setLocation(that.location);
		}

		if (node instanceof StructLiteralNode that) {
			return compileStructLiteral(scope, that);
		}

		if (node instanceof ArrayLiteralNode that) {
			throw UnimplementedException.ofPlural("array literals");
		}

		if (node instanceof TernaryOperatorNode that) {
			return compileValue(scope, that.condition).toBool()
					? compileValue(scope, that.then)
					: compileValue(scope, that.otherwise);
		}

		throw UnimplementedException.ofSingular(node.toSimpleString());

	}

	private TypeValue compileStructType(StructNode definition) {
		StructType type = new StructType(definition.name);
		type.location = definition.location;

		// inheritance goes first to keep inherited fields at the start of the struct
		if (!definition.parent.isEmpty()) {
			linkType(definition.location, definition.parent, type::inherit);
		}

		// struct members
		for (TypedEntryNode entry : definition.entries) {
			linkType(entry.location, entry.type, resolved -> {
				type.addField(entry.name, resolved, scope -> resolved.instantiate(scope, UnsetValue.UNSET), entry.location);
			});
		}

		return registerType(type);
	}

	private TypeValue compileEnumType(EnumNode definition) {
		EnumType type = new EnumType(definition.name);
		type.location = definition.location;

		for (EnumEntryNode entry : definition.entries) {
			type.addEnumeration(entry.location, entry.name, scope -> compileValue(scope, entry.value));
		}

		return registerType(type);
	}

	private void linkComponent(Scope outer, ComponentNode node, Consumer<TypeValue> callback) {
		if (node instanceof ComponentDefinitionNode definition) {
			callback.accept(compileComponentType(outer, definition));
			return;
		}

		linkType(node.location, node.name, callback);
	}

	private void addChildComponent(Scope local, ComponentType type, ComponentInstanceNode instance) {
		StructuredValue innerParameters = compileStructLiteral(local, instance.parameters);
		String name = instance.name;

		linkComponent(local, instance.component, resolved -> {

			type.addInitializer((inner, value) -> {
				Value instantiation = resolved.implicitize(local, innerParameters).instantiate(inner, UnsetValue.UNSET);

				if (instantiation instanceof ComponentValue implicit) {

					// default to placing the next instance right after the end of the previous one
					// in relation to the parent ('at' is not absolute)
					implicit.at = value.size;

					for (InstantiationNode option : instance.instantiations) {

						if (option instanceof RangeInstantiationNode range) {
							long left = compileValue(inner, range.getStart()).toLong();
							long right = compileValue(inner, range.getEnd()).toLong();

							// as per the SystemRDL specification 2.0 (5.1.2.a.3.iv) only
							// fields and signals can be instantiated using bit ranges.
							if (implicit.type.kind != ComponentKind.SIGNAL && implicit.type.kind != ComponentKind.FIELD) {
								ParseError.create(instance.location).setDetail("Component of type " + implicit.type.kind + " can't be instantiated using range instantiation!").raise();
							}

							implicit.at = Math.min(left, right);
							implicit.size = Math.max(left, right) - implicit.at + 1;
							continue;
						}

						if (option.type == InstantiationNode.Type.AT) implicit.at = compileValue(local, option.value).toLong() * 8;
						if (option.type == InstantiationNode.Type.STRIDE) implicit.stride = compileValue(local, option.value).toLong() * 8;
						if (option.type == InstantiationNode.Type.ALIGN) implicit.align = compileValue(local, option.value).toLong() * 8;
						if (option.type == InstantiationNode.Type.ARRAY) implicit.count = compileValue(local, option.value).toLong();

					}

				}

				value.values.put(name, instantiation);
				value.updateDimensions();

			});
		});
	}

	private TypeValue compileComponentType(Scope outer, ComponentDefinitionNode definition) {

		ParametricType parametric = new ParametricType(definition.name, new ParametricType.Template(definition.type, parameters -> {
			ComponentType type = new ComponentType(definition.name, definition.type, parameters);
			type.location = definition.location;

			Scope local = outer.withProperties(parameters);
			Set<String> defined = new HashSet<>();

			for (SyntaxNode node : definition.children) {

				if (node instanceof ComponentDefinitionNode compDefinition) {
					type.types().put(compDefinition.name, compileComponentType(local, compDefinition));
					continue;
				}

				if (node instanceof StructNode structDefinition) {
					type.types().put(structDefinition.name, compileStructType(structDefinition));
					continue;
				}

				if (node instanceof EnumNode enumDefinition) {
					type.types().put(enumDefinition.name, compileEnumType(enumDefinition));
					continue;
				}

				// instantiations
				if (node instanceof ExplicitInstantiationNode instantiation) {
					addChildComponent(local, type, instantiation.instance);
					continue;
				}

				if (node instanceof ComponentInstanceNode instance) {

					// this should always pass here, as all non-explicit component instantiations contain the full definition
					if (instance.component instanceof ComponentDefinitionNode compDefinition) {
						type.types().put(compDefinition.name, compileComponentType(local, compDefinition));
					}

					addChildComponent(local, type, instance);
					continue;
				}

				// properties
				if (node instanceof PropertyAssignmentNode assignment) {
					if (assignment.reference.instances.size() != 1) {
						// TODO multi-component property
						// this isn't very critical and not that often used, skipping it in I3C RDL does no harm
						// ParseError.create(assignment.location).setUnexpected("multi-component property").setUnimplemented().raise();

						Logger.warn(this, "Unimplemented multi-component property at " + assignment.location.where());
						continue;
					}

					String name = assignment.reference.instances.getFirst().name;
					ComponentType.ConstructorEntry initializer = (inner, value) -> {
						value.values.put(name, compileValue(inner, assignment.value));
					};

					if (assignment.isDefault) {
						local = local.withDefault(name, initializer);
					} else {
						defined.add(name);
						type.addInitializer(initializer);
					}
				}

			}

			local.forEachUnsetDefault(defined, entry -> {
				type.addInitializer(entry);
			});

			return type;
		}));

		parametric.location = definition.location;

		// in AST parameters are combined with the definition node
		// so here we effectively separate it back into a separate nodes
		for (SyntaxNode node : definition.parameters) {

			// parameter has no default value
			if (node instanceof TypedEntryNode typed) {
				parametric.addParameter(typed.name, findType(typed.location, typed.type), null, node.location);
				continue;
			}

			// this one is a bit messy, ValuedEntryNode should maybe extend TypedEntryNode
			// the .type.type is just the type name and .type.name is the property name, not the type name
			if (node instanceof ValuedEntryNode valued) {
				parametric.addParameter(valued.type.name, findType(valued.location, valued.type.type), params -> compileValue(params, valued.value), node.location);
				continue;
			}
		}

		return registerType(parametric.isElidable()
				? parametric.implicitize(Scope.empty(), StructuredValue.empty())
				: parametric);
	}

	private void compileTypes(Scope scope, Map<String, TypeValue> types, List<SyntaxNode> nodes) {

		for (SyntaxNode node : nodes) {
			if (node instanceof ComponentDefinitionNode definition) {
				types.put(definition.name, compileComponentType(scope, definition));
				continue;
			}

			if (node instanceof StructNode definition) {
				types.put(definition.name, compileStructType(definition));
				continue;
			}

			if (node instanceof EnumNode definition) {
				types.put(definition.name, compileEnumType(definition));
				continue;
			}

			if (node instanceof ComponentInstanceNode instance) {

				// this should always pass here, as all non-explicit component instantiations contain the full definition
				if (instance.component instanceof ComponentDefinitionNode definition) {
					types.put(definition.name, compileComponentType(scope, definition));
					continue;
				}
			}

		}
	}

	private TypeValue findType(Location location, String name) {
		if (name.isEmpty()) {
			ParseError.create(location).setDetail("Requested type of empty name").raise();
		}

		TypeValue type = types.get(name);

		if (type == null) {
			type = PrimitiveType.byName(name);

			if (type == null) {
				ParseError.create(location).setDetail("Undefined type '" + name + "' used").raise();
			}
		}

		return type;
	}

	public void compile(RootNode root) {
		compileTypes(Scope.empty(), top.types(), root.children);
	}

	public ComponentType getModel() {
		return top;
	}

}
