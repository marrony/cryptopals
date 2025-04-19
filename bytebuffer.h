#ifndef BYTEBUFFER_H
#define BYTEBUFFER_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

typedef struct {
  union {
    uint8_t* ptr;
    char* cptr;
  };
  size_t len;
} Byte_Buffer;

#define EMPTY_BYTE_BUFFER (Byte_Buffer) { .ptr = NULL, .len = 0 }

Byte_Buffer byte_buffer_slice(Byte_Buffer buffer, size_t offset, size_t len) {
  assert(offset <= buffer.len);

  size_t end = offset + len;
  if (end > buffer.len) {
    len -= end - buffer.len;
  }

  return (Byte_Buffer) { .ptr = buffer.ptr + offset, .len = len };
}

uint8_t* assert_bounds(Byte_Buffer b, size_t n, const char* file, int line) {
  if (n >= b.len) {
    fprintf(stderr, "%s:%d: Array index out of bounds. %zu >= %zu\n", file, line, n, b.len);
    exit(1);
  }
  return b.ptr+n;
}

#define AT(b, n) (*(assert_bounds((b), (n), __FILE__, __LINE__)))

void byte_buffer_print(Byte_Buffer buff, size_t nbytes) {
  for (size_t i = 0; i < buff.len; i++) {
    printf("%02x ", AT(buff, i));
    if ((i+1) % nbytes == 0) printf("\n");
  }
}

bool byte_buffer_empty(Byte_Buffer buffer) {
  return buffer.ptr == NULL && buffer.len == 0;
}

bool byte_buffer_split(Byte_Buffer content, Byte_Buffer* cursor, bool (*predicate)(int)) {
  if (byte_buffer_empty(*cursor)) {
    cursor->ptr = content.ptr;
    cursor->len = 0;
  }

  if (cursor->ptr < content.ptr || cursor->ptr >= content.ptr+content.len)
    return false;

  if (cursor->ptr+cursor->len < content.ptr || cursor->ptr+cursor->len >= content.ptr+content.len)
    return false;

  size_t start = cursor->ptr + cursor->len - content.ptr;

  if (start >= content.len) return false;

  while (start < content.len && predicate(content.ptr[start]))
    start += 1;

  cursor->ptr = content.ptr + start;

  size_t end = start;

  while (end < content.len && !predicate(content.ptr[end]))
    end += 1;

  cursor->len = end - start;

  return end > start && end <= content.len;
}

bool byte_buffer_is_line_break(int ch) {
  return ch == '\n' || ch == '\r';
}

bool byte_buffer_line(Byte_Buffer content, Byte_Buffer* cursor) {
  return byte_buffer_split(content, cursor, byte_buffer_is_line_break);
}

Byte_Buffer byte_buffer_memset(Byte_Buffer buffer, int b) {
  memset(buffer.ptr, b, buffer.len);
  return buffer;
}

Byte_Buffer byte_buffer_copy(Byte_Buffer dst, Byte_Buffer src) {
  memcpy(dst.ptr, src.ptr, dst.len < src.len ? dst.len : src.len);
  return dst;
}

#endif // BYTEBUFFER_H
