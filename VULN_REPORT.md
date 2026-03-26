# fmt Seeded Vulnerability Report

**Library:** {fmt} v8.1.1
**Branch:** OSV-2022-168
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-03-26

> **Note:** These bugs are NOT present in the upstream {fmt} codebase.
> They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-121 | Stack-buffer-overflow | `include/fmt/format.h:1131` | ASan stack-buffer-overflow | `\x00\x00\xe8\x89\x04\x23\xc7\x8a` + 8 zero bytes + `{:d}` |
| 2 | CWE-121 | Stack-buffer-overflow | `include/fmt/format.h:1180` | ASan stack-buffer-overflow | `\xff\xff\xff\xff\xff\xff\xff\xff` + 8 zero bytes + `{:o}` |
| 3 | CWE-121 | Stack-buffer-overflow | `include/fmt/chrono.h:1207` | ASan stack-buffer-overflow | 16 zero bytes + `{:%D}` |
| 4 | CWE-121 | Stack-buffer-overflow | `include/fmt/chrono.h:1215` | ASan stack-buffer-overflow | 16 zero bytes + `{:%F}` |
| 5 | CWE-190 | Signed-integer-overflow | `include/fmt/core.h:2259` | UBSan signed-integer-overflow | 16 zero bytes + `{:.2147483648d}` |

---

## Bug 1 — format_decimal Stack Buffer Off-by-One

**File:** `include/fmt/format.h`, line 1131
**Harness:** `test/fuzzing/fmt-decimal.cc`
**Sanitizer:** ASan stack-buffer-overflow

### Change

```diff
-  Char buffer[digits10<UInt>() + 1];
+  Char buffer[digits10<UInt>()];
```

### Description

The non-pointer overload of `format_decimal` (lines 1126–1134) allocates a local stack buffer to hold the decimal digit string before copying it to the output iterator. The correct size is `digits10<UInt>() + 1` because `digits10<uint64_t>()` returns 19, and `uint64_t` can produce up to 20 decimal digits (values ≥ 10^19). Shrinking the buffer to `digits10<UInt>()` (19 bytes) means that when `size == 20` — which occurs for any value ≥ 10^19 — the inner `format_decimal(buffer, value, size)` call writes one byte past the end of the stack buffer at index 19. The `write_int` fast path (no width/precision spec) always routes through this non-pointer overload, so any format string of the form `{:d}` (or `{}`, `{:}`) combined with a sufficiently large `uint64_t` value reaches this code.

### Trigger Input

```
\x00\x00\xe8\x89\x04\x23\xc7\x8a\x00\x00\x00\x00\x00\x00\x00\x00{:d}
```

The first 8 bytes encode the `uint64_t` value 10^19 = 0x8AC7230489E80000 in little-endian. The harness pads values to `fixed_size` (16 bytes), so 8 zero padding bytes follow. The format string `{:d}` routes through `write_int` → non-pointer `format_decimal` → 20-digit decimal → write to `buffer[19]` in a 19-element array.

### Reproduction

```bash
# Seed file: test/fuzzing/fmt-decimal-corpus/seed1
./fmt-decimal-fuzzer test/fuzzing/fmt-decimal-corpus/seed1
```

---

## Bug 2 — format_uint Octal Buffer Off-by-One

**File:** `include/fmt/format.h`, line 1180
**Harness:** `test/fuzzing/fmt-octal.cc`
**Sanitizer:** ASan stack-buffer-overflow

### Change

```diff
-  char buffer[num_bits<UInt>() / BASE_BITS + 1];
+  char buffer[num_bits<UInt>() / BASE_BITS];
```

### Description

The non-pointer overload of `format_uint` allocates a stack buffer for the base-converted digit string. For octal output `BASE_BITS == 3`, and `num_bits<uint64_t>() == 64`, so the correct buffer size is `64/3 + 1 == 22` (integer division gives 21, plus 1). UINT64_MAX requires exactly 22 octal digits (`1777777777777777777777`). With the buffer shrunk to 21 elements, `format_uint<3>(buffer, value, 22, ...)` advances `buffer += 22` then writes `*--buffer` on the first iteration, placing the most-significant digit at `buffer[21]` — one past the end of the 21-element array. The `{:o}` format specifier routes through this code path.

### Trigger Input

```
\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00{:o}
```

The first 8 bytes encode UINT64_MAX (0xFFFFFFFFFFFFFFFF) in little-endian, followed by 8 zero padding bytes and the format string `{:o}`. UINT64_MAX produces 22 octal digits, and the first `*--buffer` write lands at `buffer[21]` in a 21-element array.

### Reproduction

```bash
# Seed file: test/fuzzing/fmt-octal-corpus/seed1
./fmt-octal-fuzzer test/fuzzing/fmt-octal-corpus/seed1
```

---

## Bug 3 — on_us_date Stack Buffer Off-by-One

**File:** `include/fmt/chrono.h`, line 1207
**Harness:** `test/fuzzing/chrono-usdate.cc`
**Sanitizer:** ASan stack-buffer-overflow

### Change

```diff
-    char buf[8];
+    char buf[7];
```

### Description

The `on_us_date` handler formats a US-style date (MM/DD/YY) in response to the `%D` chrono format specifier. It calls `write_digit2_separated(buf, month, day, year2, '/')`, which internally builds an 8-byte packed integer from the three two-digit fields and one separator, then writes all 8 bytes to `buf` via a single `memcpy`. This write is unconditional and always exactly 8 bytes. Shrinking `buf` to 7 elements means the `memcpy` always writes one byte past the end of the stack array. Any `std::tm` value formatted with `{:%D}` triggers this path.

### Trigger Input

```
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{:%D}
```

The first 8 bytes encode `time_t = 0` (Unix epoch, 1970-01-01). The harness advances past `fixed_size` (16) bytes to read the format string, so 8 additional zero padding bytes follow the `time_t` value. `std::localtime` converts this to a `std::tm`, and `{:%D}` triggers `on_us_date` → 8-byte `memcpy` into a 7-byte buffer.

### Reproduction

```bash
# Seed file: test/fuzzing/chrono-usdate-corpus/seed1
./chrono-usdate-fuzzer test/fuzzing/chrono-usdate-corpus/seed1
```

---

## Bug 4 — on_iso_date Stack Buffer Off-by-One

**File:** `include/fmt/chrono.h`, line 1215
**Harness:** `test/fuzzing/chrono-isodate.cc`
**Sanitizer:** ASan stack-buffer-overflow

### Change

```diff
-    char buf[10];
+    char buf[9];
```

### Description

The `on_iso_date` handler formats an ISO 8601 date (YYYY-MM-DD) in response to the `%F` chrono format specifier. It first writes the century digits to `buf[0..1]` via `copy2`, then calls `write_digit2_separated(buf + 2, year_lower, month, day, '-')`. That helper always writes exactly 8 bytes starting at its first argument, meaning bytes `buf[2]` through `buf[9]` are written. The correct buffer size is 10. With `buf` shrunk to 9 elements, the final byte of the `memcpy` lands at `buf[9]`, which is one past the end of the 9-element array. Any `std::tm` with a year in the range 0–9999 formatted with `{:%F}` reaches this path.

### Trigger Input

```
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{:%F}
```

The first 8 bytes encode `time_t = 0` (1970-01-01), followed by 8 zero padding bytes and the format string `{:%F}`. Since 1970 is in the range 0–9999, `on_iso_date` takes the normal branch, writes `19` to `buf[0..1]`, then calls `write_digit2_separated(buf + 2, ...)` which writes 8 bytes through `buf[9]` — past the end of the 9-element array.

### Reproduction

```bash
# Seed file: test/fuzzing/chrono-isodate-corpus/seed1
./chrono-isodate-fuzzer test/fuzzing/chrono-isodate-corpus/seed1
```

---

## Bug 5 — parse_nonnegative_int Signed Integer Overflow

**File:** `include/fmt/core.h`, line 2259
**Harness:** `test/fuzzing/integer-width.cc`
**Sanitizer:** UBSan signed-integer-overflow

### Change

```diff
-  unsigned value = 0, prev = 0;
+  int value = 0, prev = 0;
 ...
-    value = value * 10 + unsigned(*p - '0');
+    value = value * 10 + int(*p - '0');
```

### Description

`parse_nonnegative_int` accumulates decimal digits from the format string (used for width and precision fields like `{:.NNNd}`) into an integer. The original code uses `unsigned` arithmetic, which wraps on overflow and allows the subsequent explicit overflow check to detect and reject the value. Changing the accumulator to `int` means that when the accumulated value exceeds `INT_MAX` (2147483647), signed integer overflow occurs — which is undefined behavior detected by UBSan. The overflow fires inside the `do { value = value * 10 + int(*p - '0'); }` loop before any overflow check is reached. Any format string whose precision or width field contains the value 2147483648 (or larger) triggers the overflow.

### Trigger Input

```
\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00{:.2147483648d}
```

The first 8 bytes encode `uint64_t = 42` in little-endian, followed by 8 zero padding bytes. The format string `{:.2147483648d}` contains a precision field of 2147483648 = 2^31 = INT_MAX + 1. After processing the first 9 digits "214748364", `value == 214748364`; the 10th digit '8' causes `214748364 * 10 + 8 = 2147483648 > INT_MAX`, triggering signed integer overflow.

### Reproduction

```bash
# Seed file: test/fuzzing/integer-width-corpus/seed1
./integer-width-fuzzer test/fuzzing/integer-width-corpus/seed1
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/fmt

# Compile a specific harness (replace NAME with the target):
clang++ -std=c++17 \
  -I include \
  -fsanitize=address,undefined \
  -fno-sanitize-recover=all \
  -fsanitize=fuzzer \
  -DFMT_FUZZ \
  -g -O1 \
  src/format.cc \
  test/fuzzing/NAME.cc \
  -o NAME-fuzzer

# Run with the seed corpus:
./NAME-fuzzer test/fuzzing/NAME-corpus/ -max_total_time=60

# Reproduce with a known trigger:
./NAME-fuzzer test/fuzzing/NAME-corpus/seed1
```

Or use the CMake build (reproduce mode, no libFuzzer required):

```bash
mkdir build-fuzz && cd build-fuzz
cmake .. -DFMT_FUZZ=On -DFMT_FUZZ_LINKMAIN=On -DFMT_DOC=Off -DFMT_TEST=Off
cmake --build .

# Run a seed:
./test/fuzzing/fmt-decimal-fuzzer ../test/fuzzing/fmt-decimal-corpus/seed1
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `fmt-decimal-fuzzer` | Bug 1 |
| `fmt-octal-fuzzer` | Bug 2 |
| `chrono-usdate-fuzzer` | Bug 3 |
| `chrono-isodate-fuzzer` | Bug 4 |
| `integer-width-fuzzer` | Bug 5 |

---

## Expected Sanitizer Output

### Bug 1 — ASan stack-buffer-overflow
```
==ASAN: stack-buffer-overflow on address ...
READ/WRITE of size 1 at ... thread T0
    #0 ... in fmt::v8::detail::format_decimal<char, unsigned long, ...>
    #1 ... in fmt::v8::detail::write_int<...>
    ...
SUMMARY: AddressSanitizer: stack-buffer-overflow in format_decimal
```

### Bug 2 — ASan stack-buffer-overflow
```
==ASAN: stack-buffer-overflow on address ...
READ/WRITE of size 1 at ... thread T0
    #0 ... in fmt::v8::detail::format_uint<3u, char, ...>
    #1 ... in fmt::v8::detail::write_int<...>
    ...
SUMMARY: AddressSanitizer: stack-buffer-overflow in format_uint
```

### Bug 3 — ASan stack-buffer-overflow
```
==ASAN: stack-buffer-overflow on address ...
WRITE of size 8 at ... thread T0
    #0 ... in fmt::v8::detail::write_digit2_separated
    #1 ... in fmt::v8::detail::tm_writer<...>::on_us_date
    ...
SUMMARY: AddressSanitizer: stack-buffer-overflow in write_digit2_separated
```

### Bug 4 — ASan stack-buffer-overflow
```
==ASAN: stack-buffer-overflow on address ...
WRITE of size 8 at ... thread T0
    #0 ... in fmt::v8::detail::write_digit2_separated
    #1 ... in fmt::v8::detail::tm_writer<...>::on_iso_date
    ...
SUMMARY: AddressSanitizer: stack-buffer-overflow in write_digit2_separated
```

### Bug 5 — UBSan signed-integer-overflow
```
include/fmt/core.h:2263: runtime error: signed integer overflow:
  214748364 * 10 + 8 cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior in parse_nonnegative_int
```

---

## Build System Integration

### CMakeLists.txt

```cmake
add_fuzzer(fmt-decimal.cc)
add_fuzzer(fmt-octal.cc)
add_fuzzer(chrono-usdate.cc)
add_fuzzer(chrono-isodate.cc)
add_fuzzer(integer-width.cc)
```

### Makefile (OSS-Fuzz)

```makefile
all: \
  $(OUT)/fmt-decimal-fuzzer \
  $(OUT)/fmt-decimal-fuzzer_seed_corpus.zip \
  $(OUT)/fmt-decimal-fuzzer.options \
  $(OUT)/fmt-octal-fuzzer \
  $(OUT)/fmt-octal-fuzzer_seed_corpus.zip \
  $(OUT)/fmt-octal-fuzzer.options \
  $(OUT)/chrono-usdate-fuzzer \
  $(OUT)/chrono-usdate-fuzzer_seed_corpus.zip \
  $(OUT)/chrono-usdate-fuzzer.options \
  $(OUT)/chrono-isodate-fuzzer \
  $(OUT)/chrono-isodate-fuzzer_seed_corpus.zip \
  $(OUT)/chrono-isodate-fuzzer.options \
  $(OUT)/integer-width-fuzzer \
  $(OUT)/integer-width-fuzzer_seed_corpus.zip \
  $(OUT)/integer-width-fuzzer.options
```

---

## Changelog

### 2026-03-26 — Initial bug injection

Added 5 intentional vulnerabilities in `include/fmt/format.h`, `include/fmt/chrono.h`, and `include/fmt/core.h`. Created fuzzer harnesses and seed corpora for each. Updated `test/fuzzing/CMakeLists.txt` to reference only the new harnesses.

### 2026-03-26 — Connected harnesses

Added corpus directories and seed corpora; updated CMakeLists.txt. Removed previous harnesses (chrono-duration, chrono-timepoint, float, named-arg, one-arg, two-args).

### 2026-03-26 — Replaced biased seeds with unbiased seeds

| Harness | Old seed (biased) | New seed (unbiased) | Seed bytes |
|---------|-------------------|---------------------|------------|
| `fmt-decimal` | `{:d}` only | 10^19 value + `{:d}` | `00 00 e8 89 04 23 c7 8a 00 00 00 00 00 00 00 00 7b 3a 64 7d` |
| `fmt-octal` | `{:o}` only | UINT64_MAX + `{:o}` | `ff ff ff ff ff ff ff ff 00 00 00 00 00 00 00 00 7b 3a 6f 7d` |
| `chrono-usdate` | `{:%D}` only | zero time_t + `{:%D}` | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7b 3a 25 44 7d` |
| `chrono-isodate` | `{:%F}` only | zero time_t + `{:%F}` | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7b 3a 25 46 7d` |
| `integer-width` | `{}` only | 42 + `{:.2147483648d}` | `2a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7b 3a 2e 32 31 34 37 34 38 33 36 34 38 64 7d` |

---

*This report documents intentional research vulnerabilities.
The upstream {fmt} library does not contain these bugs.*
