package io.github.secretshield.core.traversal;

import io.github.secretshield.api.exception.SecretShieldException;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

class ObjectGraphTraverserTest {

    private final ObjectGraphTraverser traverser = new ObjectGraphTraverser();

    @Test
    void visitsMapKeysValuesCollectionsArraysAndApplicationFields() {
        Map<Object, Object> root = new LinkedHashMap<>();
        root.put("credential-name", new Payload("sensitive-value"));
        root.put("items", new ArrayList<>(List.of(new int[]{7, 8})));

        Set<String> paths = new HashSet<>();
        TraversalReport report = traverser.traverse(root, (path, value) -> paths.add(path));

        assertTrue(report.isComplete());
        assertTrue(paths.contains("$"));
        assertTrue(paths.contains("$[key#0]"));
        assertTrue(paths.contains("$[value#0].password"));
        assertTrue(paths.contains("$[value#1][0][1]"));
    }

    @Test
    void detectsIdentityCycleWithoutRecursingForever() {
        Map<String, Object> cyclic = new LinkedHashMap<>();
        cyclic.put("self", cyclic);

        List<String> paths = new ArrayList<>();
        TraversalReport report = traverser.traverse(cyclic, (path, value) -> paths.add(path));

        assertEquals(1, report.cyclesDetected());
        assertFalse(report.truncated());
        assertEquals(2, report.visitedNodes());
        assertEquals(2, paths.size());
    }

    @Test
    void visitsSharedObjectOnlyOnceWithoutCallingItACycle() {
        Payload shared = new Payload("shared");
        List<Object> root = List.of(shared, shared);

        TraversalReport report = traverser.traverse(root, (path, value) -> { });

        assertEquals(0, report.cyclesDetected());
        assertEquals(3, report.visitedNodes());
    }

    @Test
    void stopsAtMaximumDepthAndMarksReportIncomplete() {
        List<Object> root = List.of(List.of("deep-value"));
        List<String> paths = new ArrayList<>();

        TraversalReport report = traverser.traverse(
                root, new TraversalLimits(1, 100), (path, value) -> paths.add(path));

        assertEquals(List.of("$", "$[0]"), paths);
        assertTrue(report.truncated());
        assertFalse(report.isComplete());
    }

    @Test
    void stopsAtMaximumNodeCountAndMarksReportIncomplete() {
        List<String> root = List.of("first", "second", "third");
        List<String> paths = new ArrayList<>();

        TraversalReport report = traverser.traverse(
                root, new TraversalLimits(10, 2), (path, value) -> paths.add(path));

        assertEquals(2, report.visitedNodes());
        assertEquals(2, paths.size());
        assertTrue(report.truncated());
    }

    @Test
    void visitsTransientFieldsButExcludesStaticFields() {
        StaticTransientPayload.STATIC_SECRET = "static";
        StaticTransientPayload payload = new StaticTransientPayload();
        Set<String> paths = new HashSet<>();

        traverser.traverse(payload, (path, value) -> paths.add(path));

        assertTrue(paths.contains("$"));
        assertFalse(paths.contains("$.STATIC_SECRET"));
        assertTrue(paths.contains("$.temporary"));
        assertTrue(paths.contains("$.visible"));
    }

    @Test
    void visitorFailureDoesNotLeakExceptionMessageOrCause() {
        String secret = "never-include-this-secret";
        SecretShieldException exception = assertThrows(
                SecretShieldException.class,
                () -> traverser.traverse(secret, (path, value) -> {
                    throw new IllegalStateException(secret);
                }));

        assertEquals("Object graph visitor failed", exception.getMessage());
        assertNull(exception.getCause());
        assertFalse(exception.toString().contains(secret));
    }

    @Test
    void nullRootProducesEmptyReport() {
        TraversalReport report = traverser.traverse(null, (path, value) -> fail("must not visit"));

        assertEquals(TraversalReport.empty(), report);
    }

    private static final class Payload {
        private final String password;

        private Payload(String password) {
            this.password = password;
        }
    }

    private static final class StaticTransientPayload {
        private static String STATIC_SECRET;
        private transient String temporary = "temporary";
        private String visible = "visible";
    }
}
