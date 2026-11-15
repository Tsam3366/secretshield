package io.github.secretshield.core.traversal;

import io.github.secretshield.api.exception.SecretShieldException;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;

/**
 * Performs bounded, depth-first traversal of common Java object graphs.
 *
 * <p>Maps (including keys and values), iterables, optionals, arrays, and
 * application objects are visited. Application-object fields are read
 * directly; getters are never invoked. Static, transient, and synthetic
 * fields are excluded. Platform objects outside the supported container
 * types are treated as leaves.</p>
 *
 * <p>The visitor receives each value synchronously. It must not retain or
 * log values because they may contain secrets. Visitor failures and
 * traversal failures are replaced with value-free exceptions.</p>
 *
 * <p>This class does not mutate the graph. A report with
 * {@link TraversalReport#isComplete()} equal to {@code false} must not be
 * interpreted as proof that all nested data was inspected.</p>
 */
public final class ObjectGraphTraverser {

    /**
     * Traverses a graph using conservative default limits.
     *
     * @param root root object
     * @param visitor receives a logical path and the value at that path
     * @return value-free traversal report
     */
    public TraversalReport traverse(Object root, BiConsumer<String, Object> visitor) {
        return traverse(root, TraversalLimits.defaults(), visitor);
    }

    /**
     * Traverses a graph without recursively consuming the Java call stack.
     *
     * @param root root object
     * @param limits maximum depth and visited values
     * @param visitor receives a logical path and the value at that path
     * @return value-free traversal report
     */
    public TraversalReport traverse(
            Object root,
            TraversalLimits limits,
            BiConsumer<String, Object> visitor) {
        Objects.requireNonNull(limits, "limits must not be null");
        Objects.requireNonNull(visitor, "visitor must not be null");

        if (root == null) {
            return TraversalReport.empty();
        }

        IdentityHashMap<Object, Boolean> visited = new IdentityHashMap<>();
        IdentityHashMap<Object, Boolean> active = new IdentityHashMap<>();
        Deque<Frame> stack = new ArrayDeque<>();
        MutableCounters counters = new MutableCounters();
        int visitedNodes = 0;
        int cyclesDetected = 0;
        boolean truncated = false;

        stack.push(new Frame(root, "$", 0));

        try {
            while (!stack.isEmpty()) {
                Frame frame = stack.peek();

                if (!frame.entered) {
                    if (visitedNodes >= limits.maxNodes()) {
                        truncated = true;
                        break;
                    }

                    frame.entered = true;
                    visitedNodes++;

                    if (isTraversable(frame.value)) {
                        visited.put(frame.value, Boolean.TRUE);
                        active.put(frame.value, Boolean.TRUE);
                    }

                    try {
                        visitor.accept(frame.path, frame.value);
                    } catch (RuntimeException ignored) {
                        throw new SecretShieldException("Object graph visitor failed");
                    }

                    frame.children = childrenOf(frame.value, frame.path, counters);
                    if (frame.depth >= limits.maxDepth()) {
                        if (frame.children.hasNext()) {
                            truncated = true;
                        }
                        stack.pop();
                        if (isTraversable(frame.value)) {
                            active.remove(frame.value);
                        }
                        continue;
                    }
                }

                if (frame.children.hasNext()) {
                    Child child = frame.children.next();
                    Object childValue = child.value();

                    if (isTraversable(childValue)) {
                        if (active.containsKey(childValue)) {
                            cyclesDetected++;
                            continue;
                        }
                        if (visited.containsKey(childValue)) {
                            // Shared references are visited once, but are not cycles.
                            continue;
                        }
                    }

                    if (visitedNodes >= limits.maxNodes()) {
                        truncated = true;
                        break;
                    }

                    stack.push(new Frame(childValue, child.path(), frame.depth + 1));
                } else {
                    stack.pop();
                    if (isTraversable(frame.value)) {
                        active.remove(frame.value);
                    }
                }
            }
        } catch (SecretShieldException exception) {
            throw exception;
        } catch (RuntimeException ignored) {
            // Do not propagate exception messages or causes from user objects.
            throw new SecretShieldException("Object graph traversal failed");
        }

        return new TraversalReport(
                visitedNodes, cyclesDetected, counters.inaccessibleFields, truncated);
    }

    private static boolean isTraversable(Object value) {
        if (value == null) {
            return false;
        }
        Class<?> type = value.getClass();
        if (type.isArray() || value instanceof Map<?, ?>
                || value instanceof Iterable<?> || value instanceof Optional<?>) {
            return true;
        }
        if (type.isPrimitive() || type.isEnum()) {
            return false;
        }

        Package valuePackage = type.getPackage();
        String packageName = valuePackage == null ? "" : valuePackage.getName();
        return !(packageName.startsWith("java.")
                || packageName.startsWith("javax.")
                || packageName.startsWith("jdk.")
                || packageName.startsWith("sun.")
                || packageName.startsWith("com.sun."));
    }

    private static Iterator<Child> childrenOf(
            Object value, String path, MutableCounters counters) {
        if (value == null) {
            return List.<Child>of().iterator();
        }
        if (value instanceof Map<?, ?> map) {
            return mapChildren(map, path);
        }
        if (value instanceof Optional<?> optional) {
            return optional.map(item -> List.of(new Child(path + ".value", item)))
                    .orElseGet(List::of).iterator();
        }
        if (value instanceof Iterable<?> iterable) {
            return iterableChildren(iterable, path);
        }
        if (value.getClass().isArray()) {
            return arrayChildren(value, path);
        }
        if (!isTraversable(value)) {
            return List.<Child>of().iterator();
        }
        return fieldChildren(value, path, counters);
    }

    private static Iterator<Child> mapChildren(Map<?, ?> map, String path) {
        Iterator<? extends Map.Entry<?, ?>> entries = map.entrySet().iterator();
        return new Iterator<>() {
            private int index;
            private Child pendingValue;

            @Override
            public boolean hasNext() {
                return pendingValue != null || entries.hasNext();
            }

            @Override
            public Child next() {
                if (pendingValue != null) {
                    Child result = pendingValue;
                    pendingValue = null;
                    return result;
                }
                Map.Entry<?, ?> entry = entries.next();
                int current = index++;
                pendingValue = new Child(path + "[value#" + current + "]", entry.getValue());
                return new Child(path + "[key#" + current + "]", entry.getKey());
            }
        };
    }

    private static Iterator<Child> iterableChildren(Iterable<?> iterable, String path) {
        Iterator<?> values = iterable.iterator();
        return new Iterator<>() {
            private int index;

            @Override
            public boolean hasNext() {
                return values.hasNext();
            }

            @Override
            public Child next() {
                int current = index++;
                return new Child(path + "[" + current + "]", values.next());
            }
        };
    }

    private static Iterator<Child> arrayChildren(Object array, String path) {
        int length = Array.getLength(array);
        return new Iterator<>() {
            private int index;

            @Override
            public boolean hasNext() {
                return index < length;
            }

            @Override
            public Child next() {
                int current = index++;
                return new Child(path + "[" + current + "]", Array.get(array, current));
            }
        };
    }

    private static Iterator<Child> fieldChildren(
            Object owner, String path, MutableCounters counters) {
        List<Field> fields = new ArrayList<>();
        try {
            for (Class<?> type = owner.getClass();
                    type != null && type != Object.class;
                    type = type.getSuperclass()) {
                fields.addAll(Arrays.asList(type.getDeclaredFields()));
            }
        } catch (RuntimeException ignored) {
            counters.inaccessibleFields++;
            return List.<Child>of().iterator();
        }

        fields.removeIf(field -> {
            int modifiers = field.getModifiers();
            return Modifier.isStatic(modifiers)
                    || Modifier.isTransient(modifiers)
                    || field.isSynthetic();
        });
        fields.sort(Comparator.comparing(Field::getName)
                .thenComparing(field -> field.getDeclaringClass().getName()));

        return new Iterator<>() {
            private int index;
            private Child next;
            private boolean ready;

            @Override
            public boolean hasNext() {
                advance();
                return ready;
            }

            @Override
            public Child next() {
                advance();
                if (!ready) {
                    throw new java.util.NoSuchElementException();
                }
                Child result = next;
                next = null;
                ready = false;
                return result;
            }

            private void advance() {
                while (!ready && index < fields.size()) {
                    Field field = fields.get(index++);
                    try {
                        if (!field.canAccess(owner) && !field.trySetAccessible()) {
                            counters.inaccessibleFields++;
                            continue;
                        }
                        next = new Child(path + "." + field.getName(), field.get(owner));
                        ready = true;
                    } catch (IllegalAccessException | RuntimeException ignored) {
                        counters.inaccessibleFields++;
                    }
                }
            }
        };
    }

    private record Child(String path, Object value) {
    }

    private static final class Frame {
        private final Object value;
        private final String path;
        private final int depth;
        private boolean entered;
        private Iterator<Child> children = List.<Child>of().iterator();

        private Frame(Object value, String path, int depth) {
            this.value = value;
            this.path = path;
            this.depth = depth;
        }
    }

    private static final class MutableCounters {
        private int inaccessibleFields;
    }
}
