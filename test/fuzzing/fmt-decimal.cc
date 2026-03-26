#include <fmt/format.h>

#include <cstdint>
#include <exception>
#include <string>

#include "fuzzer-common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size <= fixed_size) return 0;

  const uint64_t value = assign_from_buf<uint64_t>(data);
  data += fixed_size;
  size -= fixed_size;

  data_to_string fmt_str(data, size);
  try {
    std::string out;
    fmt::format_to(std::back_inserter(out), fmt_str.get(), value);
  } catch (std::exception&) {
  }
  return 0;
}
