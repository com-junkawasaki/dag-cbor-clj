# dag-cbor-clj

**Definite-length CBOR (RFC 8949) encode/decode in pure Clojure — with both a
canonical (dag-cbor key-sorted) encoder and an order-preserving one for
signing payloads. No deps, babashka-friendly.**

CBOR keeps getting hand-rolled in kotoba/IPLD codebases (CACAO issuers, Pregel
coordinators each open-code the major-type headers). This is that once.

```clojure
(require '[cbor.core :as cbor])

(cbor/encode {"a" 1 "b" [2 3]})        ;=> ^bytes, map keys sorted dag-cbor style
(cbor/decode bytes)                     ;=> {"a" 1 "b" [2 3]}
(cbor/encode-ordered [["b" 1] ["a" 2]]) ;=> ^bytes, keys in the GIVEN order
```

- **`encode`** — deterministic: map keys sorted shorter-first-then-bytewise (dag-cbor),
  so the same data always yields the same bytes (content addressing, IPLD).
- **`encode-ordered`** — a map from an ordered `[k v]` seq, keys emitted as given.
  CAIP-122 CACAO and other insertion-order-sensitive wire formats need this;
  canonical sorting would corrupt the signature payload.
- **`decode`** — maps → `{}`, arrays → `[]`, text → `String`, byte-strings → `^bytes`,
  ints → `Long`, true/false/null.

Supported major types: 0 uint · 1 negint · 2 byte-string · 3 text · 4 array ·
5 map · 7 (false/true/null). No indefinite lengths, floats, or tags — a tight
profile covering structured signing payloads and IPLD-ish data.

## Correctness

`bb test`: RFC 8949 Appendix-A vectors, canonical key-ordering, order preservation,
and encode→decode round-trips (incl. UTF-8, nesting, byte-strings, uint boundaries).

```
Ran 6 tests containing 53 assertions.
0 failures, 0 errors.
```

## License

Apache-2.0.
