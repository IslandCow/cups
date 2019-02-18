#include <stddef.h>
#include <string.h>

#include "cups/ipp.h"

namespace {

struct Buffer {
  const uint8_t *data;
  size_t len;
  size_t pos;
};

/*
 * 'ippread()' - Callback for ippReadIO.
 */
ssize_t ippread(Buffer* buffer,
             ipp_uchar_t* dst,
             size_t bytes) {
  size_t remaining_bytes = buffer->len - buffer->pos;
  size_t copied_bytes = bytes > remaining_bytes ? remaining_bytes : bytes;
  if (copied_bytes > 0) {
    memcpy(dst, buffer->data + buffer->pos, copied_bytes); 
    buffer->pos += copied_bytes;
  }

  return static_cast<ssize_t>(copied_bytes);
}

/*
 * 'fuzz_ipp_read()' - Runs ippReadIO with an arbitrary buffer.
 */
void fuzz_ipp_read(Buffer* buffer) {
  ipp_t *result = ippNew();
  ippReadIO(buffer, reinterpret_cast<ipp_iocb_t>(ippread), 1, NULL, result);
  ippDelete(result);
}

} // namespace

/*
 * Performs fuzzing. Bugs will result in crashes.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Buffer buffer = {data, size, 0};
  fuzz_ipp_read(&buffer);
  return 0;  // Non-zero return values are reserved for future use.
}
