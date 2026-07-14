#ifndef DSAA_STORAGE_ABI_H
#define DSAA_STORAGE_ABI_H

#include <stdint.h>
#include <stdbool.h>

/* Plugin lifecycle. config_json is a null-terminated UTF-8 JSON string. */
void*  dsaa_storage_create(const char* config_json);
void   dsaa_storage_destroy(void* handle);

/* File operations. Returns 0 on success, -1 on error. */
int    dsaa_open_write(void* handle, const char* path,
                       int64_t file_size, void** out_stream);
int    dsaa_open_read(void* handle, const char* path,
                      void** out_stream);
int    dsaa_delete(void* handle, const char* path);
int    dsaa_exists(void* handle, const char* path, bool* out_exists);
int    dsaa_ping(void* handle, bool* out_alive);

/* Stream I/O. Returns bytes read/written, or -1 on error. */
int64_t dsaa_stream_read(void* stream, void* buf, int64_t count);
int64_t dsaa_stream_write(void* stream, const void* buf, int64_t count);
void    dsaa_stream_close(void* stream);

#endif /* DSAA_STORAGE_ABI_H */
