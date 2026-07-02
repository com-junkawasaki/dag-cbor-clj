;; cbor.core — definite-length CBOR (RFC 8949) encode/decode.
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
;;                         byte strings as bytes, ints as Long/number, bool/nil)
;;
;; Supported major types: 0 uint · 1 negint · 2 byte-string · 3 text · 4 array ·
;; 5 map · 7 (false/true/null). No indefinite lengths, no floats, no tags — a tight
;; profile that covers structured signing payloads and IPLD-ish data.
;;
;; PORTABLE (.cljc, real on both platforms — this used to be `.clj`-only despite
;; every downstream repo's docstring calling that out as a known gap). Byte
;; buffers are `java.io.ByteArrayOutputStream`/`ByteArrayInputStream` on :clj and
;; a plain growable JS array / an atom-backed cursor over a Uint8Array on :cljs;
;; `encode`/`decode`'s public contract (bytes in, bytes/Clojure-data out) is
;; unchanged on :clj and equivalent on :cljs (Uint8Array instead of byte-array,
;; JS string instead of java.lang.String — both are just "the platform's native
;; string/byte type").
(ns cbor.core
  #?(:clj (:import (java.io ByteArrayOutputStream ByteArrayInputStream))))

;; An order-preserving map (vs. a Clojure map, which `encode` canonical-sorts).
;; Nestable: an OrderedMap value inside another OrderedMap keeps its own order —
;; what CAIP-122 CACAO needs (the {h,p,s} envelope AND p's 8 fields are ordered).
(deftype OrderedMap [pairs])
(defn ordered
  "Wrap an ordered seq of [k v] pairs as a map whose key order `encode` preserves."
  [pairs] (OrderedMap. pairs))

;; ── byte sink/source (the only platform-specific plumbing) ───────────────────
(defn- new-out []
  #?(:clj (ByteArrayOutputStream.)
     :cljs (array)))

(defn- write-byte! [o b]
  #?(:clj (.write ^ByteArrayOutputStream o (int b))
     :cljs (.push o (bit-and b 0xff))))

(defn- write-bytes! [o bs]
  #?(:clj (.write ^ByteArrayOutputStream o ^bytes bs)
     :cljs (doseq [b (seq bs)] (.push o (bit-and (int b) 0xff)))))

(defn- out->bytes [o]
  #?(:clj (.toByteArray ^ByteArrayOutputStream o)
     :cljs (js/Uint8Array. o)))

(defn- new-in [b]
  #?(:clj (ByteArrayInputStream. b)
     :cljs (atom {:data b :pos 0})))

(defn- read-byte! [in]
  #?(:clj (.read ^ByteArrayInputStream in)
     :cljs (let [{:keys [data pos]} @in]
             (if (< pos (alength data))
               (do (swap! in assoc :pos (inc pos)) (bit-and (aget data pos) 0xff))
               -1))))

(defn- read-bytes! [in n]
  #?(:clj (let [b (byte-array n)] (.read ^ByteArrayInputStream in b 0 n) b)
     :cljs (let [{:keys [data pos]} @in
                 out (.slice data pos (+ pos n))]
             (swap! in assoc :pos (+ pos n))
             out)))

(defn- bytes->str [b]
  #?(:clj (String. ^bytes b "UTF-8")
     :cljs (.decode (js/TextDecoder.) b)))

(defn- str->bytes [s]
  #?(:clj (.getBytes ^String s "UTF-8")
     :cljs (.encode (js/TextEncoder.) s)))

;; ── encode ────────────────────────────────────────────────────────────────────
(defn- write-head [o major n]
  (let [mt (bit-shift-left major 5)]
    (cond
      (< n 24)        (write-byte! o (bit-or mt n))
      (< n 0x100)     (do (write-byte! o (bit-or mt 24)) (write-byte! o n))
      (< n 0x10000)   (do (write-byte! o (bit-or mt 25))
                          (write-byte! o (bit-and (bit-shift-right n 8) 0xff))
                          (write-byte! o (bit-and n 0xff)))
      (< n 0x100000000) (do (write-byte! o (bit-or mt 26))
                            (doseq [s [24 16 8 0]] (write-byte! o (bit-and (bit-shift-right n s) 0xff))))
      :else            (do (write-byte! o (bit-or mt 27))
                           (doseq [s [56 48 40 32 24 16 8 0]]
                             (write-byte! o (bit-and (unsigned-bit-shift-right (long n) s) 0xff)))))))

(declare encode-into)

(defn- key-bytes [k]
  (str->bytes (cond (string? k) k (keyword? k) (name k) :else (str k))))

(defn- dag-cbor-key< [a b]
  (let [ka (key-bytes a) kb (key-bytes b)
        la (alength ka) lb (alength kb)]
    (if (not= la lb)
      (< la lb)                                         ; shorter key first
      (loop [i 0]                                        ; then bytewise unsigned
        (cond (= i la) false
              (not= (bit-and (aget ka i) 0xff) (bit-and (aget kb i) 0xff))
              (< (bit-and (aget ka i) 0xff) (bit-and (aget kb i) 0xff))
              :else (recur (inc i)))))))

(defn- encode-pairs [o pairs]
  (write-head o 5 (count pairs))
  (doseq [[k v] pairs]
    (encode-into o (if (keyword? k) (name k) k))
    (encode-into o v)))

(defn- bytes-like? [x]
  #?(:clj (bytes? x)
     :cljs (or (instance? js/Uint8Array x) (instance? js/Int8Array x))))

(defn- encode-into [o x]
  (cond
    (nil? x)            (write-byte! o 0xf6)
    (true? x)           (write-byte! o 0xf5)
    (false? x)          (write-byte! o 0xf4)
    (integer? x)        (if (neg? x) (write-head o 1 (- (- x) 1)) (write-head o 0 x))
    (string? x)         (let [b (str->bytes x)] (write-head o 3 (alength b)) (write-bytes! o b))
    (keyword? x)        (let [b (str->bytes (name x))] (write-head o 3 (alength b)) (write-bytes! o b))
    (bytes-like? x)     (do (write-head o 2 (alength x)) (write-bytes! o x))
    (instance? OrderedMap x) (encode-pairs o (.-pairs ^OrderedMap x))
    (map? x)            (encode-pairs o (sort-by key dag-cbor-key< (seq x)))
    (sequential? x)     (do (write-head o 4 (count x)) (doseq [e x] (encode-into o e)))
    :else (throw (ex-info "cbor: unsupported type" {:type (type x) :value x}))))

(defn encode
  "Deterministic CBOR bytes for Clojure data. Map keys are sorted dag-cbor style."
  [x]
  (let [o (new-out)] (encode-into o x) (out->bytes o)))

(defn encode-ordered
  "CBOR-encode a MAP given as an ordered seq of [k v] pairs — keys emitted in the
   given order (NOT sorted). For CAIP-122 CACAO and other order-sensitive formats."
  [pairs]
  (let [o (new-out)] (encode-pairs o pairs) (out->bytes o)))

;; ── decode ────────────────────────────────────────────────────────────────────
(defn- read-n [in cnt]
  (loop [i 0 acc 0] (if (< i cnt) (recur (inc i) (bit-or (bit-shift-left acc 8) (read-byte! in))) acc)))

(defn- read-arg [in info]
  (cond (< info 24) info
        (= info 24) (read-byte! in)
        (= info 25) (read-n in 2)
        (= info 26) (read-n in 4)
        (= info 27) (read-n in 8)
        :else (throw (ex-info "cbor: indefinite/reserved length unsupported" {:info info}))))

(declare decode-from)

(defn- decode-from [in]
  (let [ib (read-byte! in)]
    (when (neg? ib) (throw (ex-info "cbor: unexpected end of input" {})))
    (let [major (bit-shift-right ib 5) info (bit-and ib 0x1f)]
      (case (int major)
        0 (read-arg in info)
        1 (- (- (read-arg in info)) 1)
        2 (read-bytes! in (read-arg in info))
        3 (bytes->str (read-bytes! in (read-arg in info)))
        4 (vec (repeatedly (read-arg in info) #(decode-from in)))
        5 (into {} (repeatedly (read-arg in info) #(let [k (decode-from in)] [k (decode-from in)])))
        7 (case (int info) 20 false 21 true 22 nil
              (throw (ex-info "cbor: unsupported simple/float" {:info info})))
        (throw (ex-info "cbor: unsupported major type" {:major major}))))))

(defn decode
  "Decode CBOR bytes → Clojure data. Maps → {}, arrays → [], text → String,
   byte-strings → bytes (byte-array on :clj, Uint8Array on :cljs), ints →
   Long/number, true/false/null."
  [b]
  (decode-from (new-in b)))
