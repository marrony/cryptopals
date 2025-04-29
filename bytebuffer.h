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
#define AT(b, n) (*(assert_bounds((b), (n), __FILE__, __LINE__)))

Byte_Buffer byte_buffer_slice(Byte_Buffer buffer, size_t offset, size_t len);
uint8_t* assert_bounds(Byte_Buffer b, size_t n, const char* file, int line);
void byte_buffer_print(Byte_Buffer buff, size_t nbytes);
bool byte_buffer_empty(Byte_Buffer buffer);
bool byte_buffer_split(Byte_Buffer content, Byte_Buffer* cursor, bool (*predicate)(int));
bool byte_buffer_is_line_break(int ch);
bool byte_buffer_line(Byte_Buffer content, Byte_Buffer* cursor);
Byte_Buffer byte_buffer_memset(Byte_Buffer buffer, int b);
Byte_Buffer byte_buffer_copy(Byte_Buffer dst, Byte_Buffer src);
int byte_buffer_cmp(Byte_Buffer a, Byte_Buffer b);
int byte_buffer_strcmp(Byte_Buffer buf, const char* str);

typedef struct Allocator Allocator;
Byte_Buffer from_cstring(Allocator* alloc, const char* cstr);
Byte_Buffer byte_buffer_filled(Allocator* alloc, size_t size, uint8_t byte);
Byte_Buffer byte_buffer_concat(Allocator* alloc, Byte_Buffer a, Byte_Buffer b);
Byte_Buffer byte_buffer_random(Allocator* alloc, size_t size);
Byte_Buffer hex_to_bytes(Allocator* alloc, Byte_Buffer hex);
Byte_Buffer bytes_to_hex(Allocator* alloc, Byte_Buffer bytes);
Byte_Buffer base64_to_bytes(Allocator* alloc, Byte_Buffer base64);
Byte_Buffer bytes_to_base64(Allocator* alloc, Byte_Buffer bytes, bool padding);
Byte_Buffer remove_line_breaks(Byte_Buffer content);
Byte_Buffer read_entire_file(Allocator* alloc, const char* file_name);

size_t rand_between(size_t start, size_t end);

#endif // BYTEBUFFER_H

#ifdef BYTEBUFFER_IMPLEMENTATION

#ifndef BYTEBUFFER_IMPLEMENTATION_C
#define BYTEBUFFER_IMPLEMENTATION_C

#include "allocator.h"

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

int byte_buffer_cmp(Byte_Buffer a, Byte_Buffer b) {
  return memcmp(a.ptr, b.ptr, a.len < b.len ? a.len : b.len);
}

int byte_buffer_strcmp(Byte_Buffer buf, const char* str) {
  size_t len = strlen(str);
  return byte_buffer_cmp(buf, (Byte_Buffer) { .cptr = (char*)str, .len = len });
}

Byte_Buffer from_cstring(Allocator* alloc, const char* cstr) {
  size_t length = strlen(cstr);

  Byte_Buffer buffer = ALLOC(alloc, length);

  if (buffer.ptr != NULL) {
    strncpy(buffer.cptr, cstr, length);
  }

  return buffer;
}

Byte_Buffer byte_buffer_filled(Allocator* alloc, size_t size, uint8_t byte) {
  Byte_Buffer bytes = ALLOC(alloc, size);
  memset(bytes.ptr, byte, size);
  return bytes;
}

Byte_Buffer byte_buffer_concat(Allocator* alloc, Byte_Buffer a, Byte_Buffer b) {
  Byte_Buffer data = ALLOC(alloc, a.len + b.len);
  memcpy(data.ptr, a.ptr, a.len);
  memcpy(data.ptr+a.len, b.ptr, b.len);
  return data;
}

Byte_Buffer byte_buffer_random(Allocator* alloc, size_t size) {
  Byte_Buffer bytes = ALLOC(alloc, size);
  for (size_t i = 0; i < size; i++)
    AT(bytes, i) = rand_between(0, 255);
  return bytes;
}

#define FROM_HEX(ch) (((ch) >= 'a' ? (ch) - 'a' + 10 : (ch) - '0') & 0x0f)
#define TO_HEX(ch)   ((ch) >= 10 ? ((ch) - 10 + 'a') : ((ch) + '0'))

Byte_Buffer hex_to_bytes(Allocator* alloc, Byte_Buffer hex) {
  size_t size = hex.len / 2;

  Byte_Buffer buffer = ALLOC(alloc, size);
  if (buffer.ptr != NULL) {
    size_t out_size = 0;

    for (size_t i = 0; i < hex.len - 1; i += 2) {
      char ch_hi = FROM_HEX(AT(hex, i+0));
      char ch_lo = FROM_HEX(AT(hex, i+1));

      AT(buffer, out_size++) = (ch_hi << 4) | ch_lo;
    }
  }

  return buffer;
}

Byte_Buffer bytes_to_hex(Allocator* alloc, Byte_Buffer bytes) {
  Byte_Buffer buffer = ALLOC(alloc, bytes.len*2);

  if (buffer.ptr != NULL) {
    size_t out_size = 0;

    for (size_t i = 0; i < bytes.len; i++) {
      char ch_hi = AT(bytes, i) >> 4;
      char ch_lo = AT(bytes, i) & 0xf;

      AT(buffer, out_size++) = TO_HEX(ch_hi);
      AT(buffer, out_size++) = TO_HEX(ch_lo);
    }
  }

  return buffer;
}

const char base64_encode[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

const char base64_encode_url[64] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

// |xxxxxxyy|yyyyzzzz|zzwwwwww|
Byte_Buffer bytes_to_base64(Allocator* alloc, Byte_Buffer bytes, bool padding) {
  size_t bits_len = bytes.len * 8;
  size_t base64_len = (bits_len + 5) / 6;

  size_t padding_len = padding ? base64_len % 4 : 0;

  Byte_Buffer base64 = ALLOC(alloc, base64_len + padding_len);
  if (base64.ptr != NULL) {
    size_t out_size = 0;

    for (size_t in = 0; in < bytes.len - 2; in += 3) {
      unsigned char b0 = AT(bytes, in+0);
      unsigned char b1 = AT(bytes, in+1);
      unsigned char b2 = AT(bytes, in+2);

      unsigned int bits = ((unsigned int)b0 << 16) | ((unsigned int)b1 << 8) | (unsigned int)b2;

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 6) & 0x3f];
      AT(base64, out_size++) = base64_encode[bits & 0x3f];
    }

    if (bytes.len % 3 == 2) {
      unsigned char b0 = AT(bytes, bytes.len - 2);
      unsigned char b1 = AT(bytes, bytes.len - 1);

      unsigned int bits = ((unsigned int)b0 << 16) | ((unsigned int)b1 << 8);

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
      //AT(base64, out_size++) = base64_encode[(bits >> 6) & 0x3f];
    }

    if (bytes.len % 3 == 1) {
      unsigned char b0 = AT(bytes, bytes.len - 1);

      unsigned int bits = (unsigned int)b0 << 16;

      AT(base64, out_size++) = base64_encode[(bits >> 18) & 0x3f];
      AT(base64, out_size++) = base64_encode[(bits >> 12) & 0x3f];
    }

    for (size_t i = 0; i < padding_len; i++)
      AT(base64, out_size++) = '=';

    assert(out_size == base64_len+padding_len);
  }

  return base64;
}

const char base64_decode[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

const char base64_decode_url[256] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

// |xxxxxxyy|yyyyzzzz|zzwwwwww|
Byte_Buffer base64_to_bytes(Allocator* alloc, Byte_Buffer base64) {
  if (base64.ptr == NULL)
    return EMPTY_BYTE_BUFFER;

  size_t in_size = base64.len;

  while (in_size > 0 && AT(base64, in_size - 1) == '=')
    in_size--;

  size_t out_size = in_size * 6 / 8;
  Byte_Buffer bytes = ALLOC(alloc, out_size);

  size_t base64_index = 0;
  size_t bytes_index = 0;

  while (base64_index+3 < in_size) {
    int i0 = base64_decode[(int)AT(base64, base64_index++)];
    int i1 = base64_decode[(int)AT(base64, base64_index++)];
    int i2 = base64_decode[(int)AT(base64, base64_index++)];
    int i3 = base64_decode[(int)AT(base64, base64_index++)];

    int bits = (i0 << 18) | (i1 << 12) | (i2 << 6) | (i3 << 0);

    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
    AT(bytes, bytes_index++) = (bits >> 8) & 0xff;
    AT(bytes, bytes_index++) = (bits >> 0) & 0xff;
  }

  size_t diff = in_size - base64_index;

  if (diff == 3) {
    // |xxxxxxyy|yyyyzzzz|zz000000|
    int i0 = base64_decode[(int)AT(base64, base64_index+0)];
    int i1 = base64_decode[(int)AT(base64, base64_index+1)];
    int i2 = base64_decode[(int)AT(base64, base64_index+2)];

    int bits = (i0 << 18) | (i1 << 12) | (i2 << 6);
    
    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
    AT(bytes, bytes_index++) = (bits >> 8) & 0xff;
  }

  if (diff == 2) {
    // |xxxxxxyy|yyyy0000|00000000|
    int i0 = base64_decode[(int)AT(base64, base64_index+0)];
    int i1 = base64_decode[(int)AT(base64, base64_index+1)];

    int bits = (i0 << 18) | (i1 << 12);

    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
  }

  if (diff == 1) {
    // |xxxxxx00|00000000|00000000|
    int i0 = base64_decode[(int)AT(base64, base64_index)];

    int bits = (i0 << 18);

    AT(bytes, bytes_index++) = (bits >> 16) & 0xff;
  }

  return bytes;
}

Byte_Buffer remove_line_breaks(Byte_Buffer content) {
  if (content.ptr == NULL)
    return EMPTY_BYTE_BUFFER;

  char* end = content.cptr + content.len;

  char* src = content.cptr;
  char* dst = content.cptr;

  while (src < end && *src) {
    if (!isspace(*src)) *dst++ = *src;
    // if (*src != '\n' && *src != '\r') *dst++ = *src;
    src++;
  }

  return byte_buffer_slice(content, 0, dst - content.cptr);
}

Byte_Buffer read_entire_file(Allocator* alloc, const char* file_name) {
    FILE* fp = fopen(file_name, "r");
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    Byte_Buffer buffer = ALLOC(alloc, file_size);
    if (buffer.ptr == NULL)
      goto error;

    if (fread(buffer.ptr, sizeof(char), file_size, fp) != file_size)
      goto error;

    fclose(fp);
    return buffer;

error:
    fclose(fp);
    return EMPTY_BYTE_BUFFER;
}

size_t rand_between(size_t start, size_t end) {
  return rand() % (end - start + 1) + start;
}

#endif // BYTEBUFFER_IMPLEMENTATION_C

#endif // BYTEBUFFER_IMPLEMENTATION

