#include <fmt/chrono.h>

#include <cstdint>
#include <ctime>
#include <exception>
#include <string>

#include "fuzzer-common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size <= fixed_size) return 0;

  const std::time_t t = assign_from_buf<std::time_t>(data);
  data += fixed_size;
  size -= fixed_size;

  const std::tm* tm_ptr = std::localtime(&t);
  if (!tm_ptr) return 0;

  data_to_string fmt_str(data, size);
  try {
    std::string out;
    fmt::format_to(std::back_inserter(out), fmt_str.get(), *tm_ptr);
  } catch (std::exception&) {
  }
  return 0;
}
