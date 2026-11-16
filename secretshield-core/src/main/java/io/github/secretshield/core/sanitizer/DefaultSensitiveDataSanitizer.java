package io.github.secretshield.core.sanitizer;

import io.github.secretshield.api.detector.DetectionInput;
import io.github.secretshield.api.detector.DetectionResult;
import io.github.secretshield.api.detector.SecretDetector;
import io.github.secretshield.api.exception.SecretShieldException;
import io.github.secretshield.api.masking.MaskingType;
import io.github.secretshield.api.model.DataLocation;
import io.github.secretshield.api.model.SecretCategory;
import io.github.secretshield.api.model.SecretFinding;
import io.github.secretshield.api.sanitizer.SanitizationResult;
import io.github.secretshield.api.sanitizer.SensitiveDataSanitizer;
import io.github.secretshield.core.detector.rules.FieldNameDetectionRule;
import io.github.secretshield.core.masking.DefaultMaskingEngine;
import io.github.secretshield.core.traversal.TraversalLimits;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Creates a detached, normalized copy of common Java object graphs.
 *
 * <p>Maps become linked maps, collections and arrays become lists, and
 * application objects become maps of instance field names to sanitized
 * values. Cycles and shared references are preserved by object identity.</p>
 *
 * <p>Unsupported platform objects, inaccessible fields, ambiguous map keys,
 * detector failures, and resource-limit violations fail the entire operation.
 * No partially sanitized graph or original-input fallback is returned.</p>
 */
public final class DefaultSensitiveDataSanitizer implements SensitiveDataSanitizer {
    private static final int MAX_STRING_LENGTH = 65_536;
    private static final int MAX_FIELD_NAME_LENGTH = 128;
    private static final String OPAQUE_VALUE = "opaque";

    private final SecretDetector detector;
    private final DefaultMaskingEngine maskingEngine = new DefaultMaskingEngine();
    private final FieldNameDetectionRule fieldNameRule = new FieldNameDetectionRule();
    private final TraversalLimits defaultLimits;

    public DefaultSensitiveDataSanitizer(SecretDetector detector) {
        this(detector, TraversalLimits.defaults());
    }

    public DefaultSensitiveDataSanitizer(SecretDetector detector, TraversalLimits defaultLimits) {
        this.detector = Objects.requireNonNull(detector, "detector must not be null");
        this.defaultLimits = Objects.requireNonNull(defaultLimits, "defaultLimits must not be null");
    }

    @Override
    public SanitizationResult sanitize(Object input) {
        return sanitize(input, defaultLimits);
    }

    /**
     * Sanitizes using explicit per-operation depth and node limits.
     *
     * @param input source graph
     * @param limits traversal limits; map keys count as visited nodes
     * @return fully sanitized normalized graph
     */
    public SanitizationResult sanitize(Object input, TraversalLimits limits) {
        Objects.requireNonNull(limits, "limits must not be null");
        if (input == null) {
            return new SanitizationResult(null, 0, 0, 0);
        }

        State state = new State(limits);
        Object[] root = new Object[1];
        Deque<Runnable> work = new ArrayDeque<>();
        work.push(() -> processValue(input, null, "$", 0, value -> root[0] = value, state, work));

        try {
            while (!work.isEmpty()) {
                work.pop().run();
            }
            return new SanitizationResult(
                    root[0], state.visitedNodes, state.maskedValues, state.cyclesDetected);
        } catch (RuntimeException ignored) {
            // Do not retain or expose exception messages, causes, or source values.
            throw new SecretShieldException(
                    "Sanitization failed; no sanitized result was produced");
        }
    }

    private void processValue(
            Object source,
            String fieldName,
            String path,
            int depth,
            Consumer<Object> assignment,
            State state,
            Deque<Runnable> work) {
        state.visit(depth);

        if (source == null) {
            assignment.accept(null);
            return;
        }

        if (source instanceof String value) {
            assignment.accept(protectString(value, fieldName, path, state));
            return;
        }

        Optional<SecretFinding> fieldFinding = detectFieldName(fieldName, path);
        if (fieldFinding.isPresent()) {
            assignment.accept(maskOpaque(maskingType(List.of(fieldFinding.get())), state));
            return;
        }

        if (isOpaqueCharacterOrByteArray(source)) {
            int length = Array.getLength(source);
            assignment.accept(length == 0 ? new ArrayList<>() : maskOpaque(MaskingType.FULL_MASK, state));
            return;
        }

        if (source instanceof Optional<?> optional) {
            if (optional.isEmpty()) {
                assignment.accept(null);
            } else {
                work.push(() -> processValue(
                        optional.get(), null, path + ".value", depth + 1,
                        assignment, state, work));
            }
            return;
        }

        if (isSafeScalar(source)) {
            assignment.accept(source instanceof Enum<?> value ? value.name() : source);
            return;
        }

        Object existingCopy = state.copies.get(source);
        if (existingCopy != null) {
            if (state.active.containsKey(source)) {
                state.cyclesDetected++;
            }
            assignment.accept(existingCopy);
            return;
        }

        if (source instanceof Map<?, ?> map) {
            Map<Object, Object> copy = new LinkedHashMap<>();
            state.remember(source, copy);
            assignment.accept(copy);
            Iterator<? extends Map.Entry<?, ?>> entries = map.entrySet().iterator();
            int[] index = {0};
            work.push(() -> state.active.remove(source));
            work.push(() -> processMapNext(entries, copy, path, depth, index, state, work));
            return;
        }

        if (source instanceof Collection<?> collection) {
            List<Object> copy = new ArrayList<>();
            state.remember(source, copy);
            assignment.accept(copy);
            Iterator<?> values = collection.iterator();
            int[] index = {0};
            work.push(() -> state.active.remove(source));
            work.push(() -> processCollectionNext(values, copy, path, depth, index, state, work));
            return;
        }

        if (source.getClass().isArray()) {
            List<Object> copy = new ArrayList<>();
            state.remember(source, copy);
            assignment.accept(copy);
            int length = Array.getLength(source);
            int[] index = {0};
            work.push(() -> state.active.remove(source));
            work.push(() -> processArrayNext(source, length, copy, path, depth, index, state, work));
            return;
        }

        if (isPlatformType(source.getClass())) {
            throw new IllegalStateException("Unsupported platform value");
        }

        List<Field> fields = instanceFields(source.getClass());
        Map<String, Object> copy = new LinkedHashMap<>();
        state.remember(source, copy);
        assignment.accept(copy);
        int[] index = {0};
        work.push(() -> state.active.remove(source));
        work.push(() -> processFieldNext(source, fields, copy, path, depth, index, state, work));
    }

    private void processMapNext(
            Iterator<? extends Map.Entry<?, ?>> entries,
            Map<Object, Object> output,
            String path,
            int depth,
            int[] index,
            State state,
            Deque<Runnable> work) {
        if (!entries.hasNext()) {
            return;
        }

        Map.Entry<?, ?> entry = entries.next();
        int current = index[0]++;
        Object originalKey = entry.getKey();
        Object originalValue = entry.getValue();
        Object safeKey = sanitizeMapKey(
                originalKey, path + "[key#" + current + "]", depth + 1, state);
        String fieldName = originalKey instanceof String key ? key : null;

        work.push(() -> processMapNext(entries, output, path, depth, index, state, work));
        work.push(() -> processValue(
                originalValue, fieldName, path + "[value#" + current + "]", depth + 1,
                value -> {
                    if (output.containsKey(safeKey)) {
                        throw new IllegalStateException("Sanitized map key collision");
                    }
                    output.put(safeKey, value);
                },
                state, work));
    }

    private void processCollectionNext(
            Iterator<?> values,
            List<Object> output,
            String path,
            int depth,
            int[] index,
            State state,
            Deque<Runnable> work) {
        if (!values.hasNext()) {
            return;
        }

        Object child = values.next();
        int current = index[0]++;
        work.push(() -> processCollectionNext(values, output, path, depth, index, state, work));
        work.push(() -> processValue(
                child, null, path + "[" + current + "]", depth + 1,
                output::add, state, work));
    }

    private void processArrayNext(
            Object source,
            int length,
            List<Object> output,
            String path,
            int depth,
            int[] index,
            State state,
            Deque<Runnable> work) {
        if (index[0] >= length) {
            return;
        }

        int current = index[0]++;
        Object child = Array.get(source, current);
        work.push(() -> processArrayNext(source, length, output, path, depth, index, state, work));
        work.push(() -> processValue(
                child, null, path + "[" + current + "]", depth + 1,
                output::add, state, work));
    }

    private void processFieldNext(
            Object source,
            List<Field> fields,
            Map<String, Object> output,
            String path,
            int depth,
            int[] index,
            State state,
            Deque<Runnable> work) {
        if (index[0] >= fields.size()) {
            return;
        }

        Field field = fields.get(index[0]++);
        try {
            if (!field.canAccess(source) && !field.trySetAccessible()) {
                throw new IllegalStateException("Inaccessible field");
            }
            Object child = field.get(source);
            String fieldName = field.getName();
            work.push(() -> processFieldNext(
                    source, fields, output, path, depth, index, state, work));
            work.push(() -> processValue(
                    child, fieldName, path + "." + fieldName, depth + 1,
                    value -> {
                        if (output.containsKey(fieldName)) {
                            throw new IllegalStateException("Ambiguous field name");
                        }
                        output.put(fieldName, value);
                    },
                    state, work));
        } catch (IllegalAccessException | RuntimeException ignored) {
            throw new IllegalStateException("Field sanitization failed");
        }
    }

    private Object sanitizeMapKey(Object key, String path, int depth, State state) {
        state.visit(depth);
        if (key == null) {
            return null;
        }
        if (key instanceof String value) {
            return protectString(value, null, path, state);
        }
        if (!isSafeScalar(key)) {
            throw new IllegalStateException("Unsupported map key");
        }
        return key instanceof Enum<?> value ? value.name() : key;
    }

    private String protectString(String value, String fieldName, String path, State state) {
        Optional<SecretFinding> fieldFinding = detectFieldName(fieldName, path);
        if (fieldFinding.isPresent()) {
            return maskString(value, maskingType(List.of(fieldFinding.get())), state);
        }
        if (value.length() > MAX_STRING_LENGTH) {
            throw new IllegalStateException("Candidate string exceeds inspection limit");
        }

        DetectionResult result = detector.detect(
                new DetectionInput(fieldName, new DataLocation(path), value));
        if (!result.hasFindings()) {
            return value;
        }
        return maskString(value, maskingType(result.findings()), state);
    }

    private Optional<SecretFinding> detectFieldName(String fieldName, String path) {
        if (fieldName == null || fieldName.length() > MAX_FIELD_NAME_LENGTH) {
            return Optional.empty();
        }
        return fieldNameRule.detect(
                new DetectionInput(fieldName, new DataLocation(path), "non-string-value"));
    }

    private String maskString(String value, MaskingType type, State state) {
        String protectedValue = maskingEngine.mask(value, type);
        if (protectedValue == null) {
            throw new IllegalStateException("Masking did not protect the candidate");
        }
        state.maskedValues++;
        return protectedValue;
    }

    private String maskOpaque(MaskingType type, State state) {
        MaskingType effectiveType = type == MaskingType.PARTIAL_MASK
                ? MaskingType.FULL_MASK : type;
        String marker = maskingEngine.mask(OPAQUE_VALUE, effectiveType);
        if (marker == null || marker.contains(OPAQUE_VALUE)) {
            throw new IllegalStateException("Opaque value masking failed");
        }
        state.maskedValues++;
        return marker;
    }

    private static MaskingType maskingType(List<SecretFinding> findings) {
        boolean privateKey = false;
        boolean partial = false;
        for (SecretFinding finding : findings) {
            SecretCategory category = finding.category();
            if (category == SecretCategory.EMAIL || category == SecretCategory.PHONE_NUMBER) {
                partial = true;
            } else if (category == SecretCategory.PRIVATE_KEY) {
                privateKey = true;
            } else {
                return MaskingType.FULL_MASK;
            }
        }
        if (privateKey) {
            return MaskingType.REDACT;
        }
        return partial ? MaskingType.PARTIAL_MASK : MaskingType.FULL_MASK;
    }

    private static boolean isOpaqueCharacterOrByteArray(Object value) {
        if (!value.getClass().isArray()) {
            return false;
        }
        Class<?> component = value.getClass().getComponentType();
        return component == byte.class || component == Byte.class
                || component == char.class || component == Character.class;
    }

    private static boolean isSafeScalar(Object value) {
        Class<?> type = value.getClass();
        return type == Boolean.class || type == Character.class
                || type == Byte.class || type == Short.class
                || type == Integer.class || type == Long.class
                || type == Float.class || type == Double.class
                || type == BigInteger.class || type == BigDecimal.class
                || type == UUID.class || value instanceof Enum<?>
                || (value instanceof TemporalAccessor
                    && type.getName().startsWith("java.time.")
                    && Modifier.isFinal(type.getModifiers()));
    }

    private static boolean isPlatformType(Class<?> type) {
        String name = type.getName();
        return name.startsWith("java.") || name.startsWith("javax.")
                || name.startsWith("jdk.") || name.startsWith("sun.")
                || name.startsWith("com.sun.");
    }

    private static List<Field> instanceFields(Class<?> type) {
        List<Field> fields = new ArrayList<>();
        for (Class<?> current = type; current != null && current != Object.class;
                current = current.getSuperclass()) {
            fields.addAll(List.of(current.getDeclaredFields()));
        }
        fields.removeIf(field -> Modifier.isStatic(field.getModifiers()));
        fields.sort(Comparator.comparing(Field::getName)
                .thenComparing(field -> field.getDeclaringClass().getName()));
        return fields;
    }

    private static final class State {
        private final TraversalLimits limits;
        private final IdentityHashMap<Object, Object> copies = new IdentityHashMap<>();
        private final IdentityHashMap<Object, Boolean> active = new IdentityHashMap<>();
        private int visitedNodes;
        private int maskedValues;
        private int cyclesDetected;

        private State(TraversalLimits limits) {
            this.limits = limits;
        }

        private void visit(int depth) {
            if (depth > limits.maxDepth() || visitedNodes >= limits.maxNodes()) {
                throw new IllegalStateException("Sanitization resource limit exceeded");
            }
            visitedNodes++;
        }

        private void remember(Object source, Object copy) {
            copies.put(source, copy);
            active.put(source, Boolean.TRUE);
        }
    }
}
