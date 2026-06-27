;; cbor.core — definite-length CBOR (RFC 8949) encode/decode in pure Clojure.
;;
;; Across a kotoba/IPLD codebase CBOR keeps getting hand-rolled — the CACAO leash
;; issuer, the apqc/kabuto/isco coordinators each open-code the major-type headers.
;; This is that once, with two encoders:
;;
;;   (encode x)          — canonical/deterministic: map keys sorted dag-cbor style
;;                         (shorter key first, then bytewise) → stable bytes for IPLD
;;   (encode-ordered ps) — a map from an ORDERED [k v] seq, keys emitted as given
;;                         (CAIP-122 CACAO and other insertion-order-sensitive wire
;;                         formats need this — canonical sorting would corrupt them)
;;
;;   (decode bytes)      — → Clojure data (maps as {}, arrays as [], text as String,
;;                         byte strings as ^bytes, ints as Long, bool/nil)
;;
;; Supported major types: 0 uint · 1 negint · 2 byte-string · 3 text · 4 array ·
;; 5 map · 7 (false/true/null). No indefinite lengths, no floats, no tags — a tight
;; profile that covers structured signing payloads and IPLD-ish data. stdlib only.
(ns cbor.core
  (:import (java.io ByteArrayOutputStream ByteArrayInputStream)))

;; An order-preserving map (vs. a Clojure map, which `encode` canonical-sorts).
;; Nestable: an OrderedMap value inside another OrderedMap keeps its own order —
;; what CAIP-122 CACAO needs (the {h,p,s} envelope AND p's 8 fields are ordered).
(deftype OrderedMap [pairs])
(defn ordered
  "Wrap an ordered seq of [k v] pairs as a map whose key order `encode` preserves."
  [pairs] (OrderedMap. pairs))

;; ── encode ────────────────────────────────────────────────────────────────────
(defn- write-head [^ByteArrayOutputStream o major n]
  (let [mt (bit-shift-left major 5)]
    (cond
      (< n 24)        (.write o (int (bit-or mt n)))
      (< n 0x100)     (do (.write o (int (bit-or mt 24))) (.write o (int n)))
      (< n 0x10000)   (do (.write o (int (bit-or mt 25)))
                          (.write o (int (bit-and (bit-shift-right n 8) 0xff)))
                          (.write o (int (bit-and n 0xff))))
      (< n 0x100000000) (do (.write o (int (bit-or mt 26)))
                            (doseq [s [24 16 8 0]] (.write o (int (bit-and (bit-shift-right n s) 0xff)))))
      :else            (do (.write o (int (bit-or mt 27)))
                           (doseq [s [56 48 40 32 24 16 8 0]]
                             (.write o (int (bit-and (unsigned-bit-shift-right (long n) s) 0xff))))))))

(declare encode-into)

(defn- key-bytes ^bytes [k]
  (.getBytes (cond (string? k) k (keyword? k) (name k) :else (str k)) "UTF-8"))

(defn- dag-cbor-key< [a b]
  (let [ka (key-bytes a) kb (key-bytes b)]
    (if (not= (count ka) (count kb))
      (< (count ka) (count kb))                       ; shorter key first
      (loop [i 0]                                      ; then bytewise unsigned
        (cond (= i (count ka)) false
              (not= (bit-and (aget ka i) 0xff) (bit-and (aget kb i) 0xff))
              (< (bit-and (aget ka i) 0xff) (bit-and (aget kb i) 0xff))
              :else (recur (inc i)))))))

(defn- encode-pairs [^ByteArrayOutputStream o pairs]
  (write-head o 5 (count pairs))
  (doseq [[k v] pairs]
    (encode-into o (if (keyword? k) (name k) k))
    (encode-into o v)))

(defn- encode-into [^ByteArrayOutputStream o x]
  (cond
    (nil? x)            (.write o 0xf6)
    (true? x)           (.write o 0xf5)
    (false? x)          (.write o 0xf4)
    (integer? x)        (if (neg? x) (write-head o 1 (- (- x) 1)) (write-head o 0 x))
    (string? x)         (let [b (.getBytes ^String x "UTF-8")] (write-head o 3 (count b)) (.write o b))
    (keyword? x)        (let [b (.getBytes (name x) "UTF-8")] (write-head o 3 (count b)) (.write o b))
    (bytes? x)          (do (write-head o 2 (count x)) (.write o ^bytes x))
    (instance? OrderedMap x) (encode-pairs o (.-pairs ^OrderedMap x))
    (map? x)            (encode-pairs o (sort-by key dag-cbor-key< (seq x)))
    (sequential? x)     (do (write-head o 4 (count x)) (doseq [e x] (encode-into o e)))
    :else (throw (ex-info "cbor: unsupported type" {:type (type x) :value x}))))

(defn encode
  "Deterministic CBOR bytes for Clojure data. Map keys are sorted dag-cbor style."
  ^bytes [x]
  (let [o (ByteArrayOutputStream.)] (encode-into o x) (.toByteArray o)))

(defn encode-ordered
  "CBOR-encode a MAP given as an ordered seq of [k v] pairs — keys emitted in the
   given order (NOT sorted). For CAIP-122 CACAO and other order-sensitive formats."
  ^bytes [pairs]
  (let [o (ByteArrayOutputStream.)] (encode-pairs o pairs) (.toByteArray o)))

;; ── decode ────────────────────────────────────────────────────────────────────
(defn- read-n [^ByteArrayInputStream in cnt]
  (loop [i 0 acc 0] (if (< i cnt) (recur (inc i) (bit-or (bit-shift-left acc 8) (.read in))) acc)))

(defn- read-arg [^ByteArrayInputStream in info]
  (cond (< info 24) info
        (= info 24) (.read in)
        (= info 25) (read-n in 2)
        (= info 26) (read-n in 4)
        (= info 27) (read-n in 8)
        :else (throw (ex-info "cbor: indefinite/reserved length unsupported" {:info info}))))

(declare decode-from)

(defn- read-bytes ^bytes [^ByteArrayInputStream in n]
  (let [b (byte-array n)] (.read in b 0 n) b))

(defn- decode-from [^ByteArrayInputStream in]
  (let [ib (.read in)]
    (when (neg? ib) (throw (ex-info "cbor: unexpected end of input" {})))
    (let [major (bit-shift-right ib 5) info (bit-and ib 0x1f)]
      (case (int major)
        0 (read-arg in info)
        1 (- (- (read-arg in info)) 1)
        2 (read-bytes in (read-arg in info))
        3 (String. (read-bytes in (read-arg in info)) "UTF-8")
        4 (vec (repeatedly (read-arg in info) #(decode-from in)))
        5 (into {} (repeatedly (read-arg in info) #(let [k (decode-from in)] [k (decode-from in)])))
        7 (case (int info) 20 false 21 true 22 nil
              (throw (ex-info "cbor: unsupported simple/float" {:info info})))
        (throw (ex-info "cbor: unsupported major type" {:major major}))))))

(defn decode
  "Decode CBOR bytes → Clojure data. Maps → {}, arrays → [], text → String,
   byte-strings → ^bytes, ints → Long, true/false/null."
  [^bytes b]
  (decode-from (ByteArrayInputStream. b)))
