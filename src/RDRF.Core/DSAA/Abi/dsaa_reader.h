#ifndef DSAA_READER_ABI_H
#define DSAA_READER_ABI_H

#include <stdint.h>
#include <stdbool.h>

/* Opaque backup handle */
typedef struct DsaaBackup DsaaBackup;

/* Open and close a backup by its .indrdrf file path. Returns NULL on failure. */
DsaaBackup* dsaa_open(const char* index_path, const char* password);
void        dsaa_close(DsaaBackup* handle);

/* Metadata */
int64_t     dsaa_file_size(DsaaBackup* handle);
int         dsaa_fragment_count(DsaaBackup* handle);
const char* dsaa_original_name(DsaaBackup* handle);
const char* dsaa_strategy(DsaaBackup* handle);

/* Full-file sequential read (restores then reads). Returns bytes read, 0 at EOF, -1 on error. */
int64_t     dsaa_read(DsaaBackup* handle, void* buf, int64_t count);

/* Fragment-level random access. Returns bytes read, or -1 on error. */
int64_t     dsaa_read_fragment(DsaaBackup* handle, int index,
                               void* buf, int64_t max_bytes);

#endif /* DSAA_READER_ABI_H */
