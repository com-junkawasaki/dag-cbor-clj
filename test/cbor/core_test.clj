(ns cbor.core-test
  (:require [clojure.test :refer [deftest is]]
            [cbor.core :as cbor]))

(defn- hx ^String [^bytes b] (apply str (map #(format "%02x" (bit-and (int %) 0xff)) b)))
(defn- enc [x] (hx (cbor/encode x)))

;; ── RFC 8949 Appendix-A vectors ───────────────────────────────────────────────
(deftest rfc8949-vectors
  (is (= "00" (enc 0)))
  (is (= "0a" (enc 10)))
  (is (= "17" (enc 23)))
  (is (= "1818" (enc 24)))
  (is (= "1864" (enc 100)))
  (is (= "1903e8" (enc 1000)))
  (is (= "1a000f4240" (enc 1000000)))
  (is (= "20" (enc -1)))
  (is (= "3863" (enc -100)))
  (is (= "60" (enc "")))
  (is (= "6161" (enc "a")))
  (is (= "6449455446" (enc "IETF")))
  (is (= "80" (enc [])))
  (is (= "83010203" (enc [1 2 3])))
  (is (= "a0" (enc {})))
  (is (= "f4" (enc false)))
  (is (= "f5" (enc true)))
  (is (= "f6" (enc nil)))
  ;; map {"a":1,"b":[2,3]}  → a2 6161 01 6162 820203
  (is (= "a26161016162820203" (enc {"a" 1 "b" [2 3]}))))

;; ── canonical dag-cbor key ordering (shorter first, then bytewise) ────────────
(deftest canonical-key-order
  ;; canonical sort is input-order-independent: a < b < aa regardless of insertion
  (is (= (enc (array-map "aa" 3 "b" 2 "a" 1))
         (enc (array-map "a" 1 "aa" 3 "b" 2))))
  ;; exact bytes: a3 "a"(6161)01 "b"(6162)02 "aa"(626161)03
  (is (= "a361610161620262616103" (enc (array-map "aa" 3 "b" 2 "a" 1)))))

;; ── encode-ordered preserves the given order (CACAO-style) ────────────────────
(deftest encode-ordered-keeps-order
  ;; pairs b,a emitted in order → header a2, "b"(6162) 01, "a"(6161) 02 — NOT sorted
  (is (= "a2616201616102" (hx (cbor/encode-ordered [["b" 1] ["a" 2]]))))
  (is (not= (hx (cbor/encode-ordered [["b" 1] ["a" 2]])) (enc {"b" 1 "a" 2}))
      "ordered ≠ canonical when input is unsorted")
  (is (= {"b" 1 "a" 2} (cbor/decode (cbor/encode-ordered [["b" 1] ["a" 2]])))))

;; ── round-trips ───────────────────────────────────────────────────────────────
(deftest roundtrips
  (doseq [x [0 1 23 24 255 256 65535 65536 1000000 -1 -100 -1000000
             "" "hello" "日本語"
             [] [1 2 3] ["a" ["b" ["c"]]]
             {} {"k" "v"} {"a" 1 "b" [2 3] "c" {"d" true "e" nil}}
             true false nil]]
    (is (= x (cbor/decode (cbor/encode x))) (str "roundtrip " (pr-str x)))))

(deftest byte-string-roundtrip
  (let [b (byte-array (map unchecked-byte [0 1 2 250 255]))
        dec (cbor/decode (cbor/encode b))]
    (is (= (seq b) (seq dec)))))

(deftest big-uint-and-negint
  (is (= "1affffffff" (enc 0xffffffff)))               ; uint32 max → 4-byte form
  (is (= "1b0000000100000000" (enc 0x100000000)))      ; one past uint32 → 8-byte form
  (is (= 4294967295 (cbor/decode (cbor/encode 4294967295))))
  (is (= 4294967296 (cbor/decode (cbor/encode 4294967296)))))

;; ── nested order-preserving maps (CACAO envelope shape) ───────────────────────
(deftest nested-ordered
  ;; {h:{t:"x"}, p:{b:1,a:2}, s:{t:"E"}} with EVERY level order-preserved
  (let [c (cbor/encode (cbor/ordered [["h" (cbor/ordered [["t" "x"]])]
                                      ["p" (cbor/ordered [["b" 1] ["a" 2]])]
                                      ["s" (cbor/ordered [["t" "E"]])]]))]
    ;; decodes back to the same data (as plain maps)
    (is (= {"h" {"t" "x"} "p" {"b" 1 "a" 2} "s" {"t" "E"}} (cbor/decode c)))
    ;; p's bytes keep b-before-a (61 62 = "b" first), not a-before-b
    (is (clojure.string/includes? (hx c) "616201616102"))))
