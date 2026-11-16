# Bounded object graph traversal

The core module provides `ObjectGraphTraverser` as a bounded, iterative traversal primitive for sanitization.

## Supported values

- Map keys and values (map keys are represented by numeric path segments, never their contents)
- `Iterable` elements
- `Optional` contents
- Object and primitive arrays
- Application objects through directly readable instance fields

Application-object traversal does not invoke getters. Static fields are excluded; transient and synthetic instance fields are included. Platform objects outside the supported container types are treated as leaves. Callers should convert unsupported platform types to safe application data before sanitization if they may contain sensitive content.

## Resource controls

`TraversalLimits` caps depth and the total number of visited values. The root is depth zero and counts as one visited value. Defaults are 32 levels and 10,000 values. Traversal uses an explicit stack, so graph depth does not consume the Java call stack.

Identity tracking distinguishes a back-edge to an object on the active traversal path (a cycle) from a shared object referenced more than once. Shared objects are visited once.

## Incomplete traversal

The `TraversalReport` exposes cycle count, inaccessible field count, and whether configured limits truncated traversal. A report is complete only when no limit was reached and no fields were inaccessible. Consumers that require complete protection must fail closed when `isComplete()` is false; they must not return the original object as a fallback.

## Sensitive-value handling

The visitor receives raw object references synchronously because it must inspect them. It must not retain, log, or include those values in diagnostics. Traversal reports retain only counters and flags. Visitor and traversal exceptions are replaced with generic value-free messages and do not retain the original exception as a cause.
