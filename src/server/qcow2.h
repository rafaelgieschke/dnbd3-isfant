#ifndef _QCOW2_H_
#define _QCOW2_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

// Forward declaration for the qcow2 file handle
typedef struct _qcow2_handle qcow2_handle_t;

/**
 * Check if a file is a qcow2 image
 * Returns true if the file is a qcow2 image, false otherwise
 */
bool qcow2_is_qcow2(const char *filename);

/**
 * Open a qcow2 file
 * Returns a handle to the opened qcow2 file, or NULL on error
 */
qcow2_handle_t* qcow2_open(const char *filename);

/**
 * Close a qcow2 file
 */
void qcow2_close(qcow2_handle_t *handle);

/**
 * Get the virtual size of the qcow2 image
 * Returns the size in bytes, or 0 on error
 */
uint64_t qcow2_get_size(qcow2_handle_t *handle);

/**
 * Read data from a qcow2 file at a specific offset
 * Returns the number of bytes read, or -1 on error
 */
ssize_t qcow2_read(qcow2_handle_t *handle, void *buffer, size_t size, uint64_t offset);

#endif /* _QCOW2_H_ */
