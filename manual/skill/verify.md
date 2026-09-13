# igNTP: verification

1. Record Cangjie/CJPM versions and the source revision.
2. Build serially with `cjpm build -j1`.
3. Run the emitted test executable directly; require a nonzero exit for a retained negative control where supplied.
4. Build a separate consumer from the README using the extracted source package.
5. Record package checksum, actual contents, dependencies and runtime result. Keep unavailable peers separate from passes.

Tests alone do not prove registry publication or complete protocol conformance. See [operations](../docs/05-operations.md).
