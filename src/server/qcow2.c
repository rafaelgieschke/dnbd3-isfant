#include "qcow2.h"
#include "helper.h"

#include <libqcow.h>
#include <stdlib.h>
#include <string.h>

struct _qcow2_handle {
	libqcow_file_t *qcow_file;
	libqcow_error_t *error;
};

bool qcow2_is_qcow2(const char *filename)
{
	libqcow_error_t *error = NULL;
	int result = libqcow_check_file_signature( filename, &error );
	if ( error != NULL ) {
		libqcow_error_free( &error );
	}
	return result == 1;
}

qcow2_handle_t* qcow2_open(const char *filename)
{
	qcow2_handle_t *handle = malloc( sizeof(qcow2_handle_t) );
	if ( handle == NULL ) {
		return NULL;
	}
	
	handle->error = NULL;
	
	if ( libqcow_file_initialize( &handle->qcow_file, &handle->error ) != 1 ) {
		logadd( LOG_ERROR, "Failed to initialize qcow2 file handle for '%s'", filename );
		if ( handle->error != NULL ) {
			libqcow_error_free( &handle->error );
		}
		free( handle );
		return NULL;
	}
	
	if ( libqcow_file_open( handle->qcow_file, filename, LIBQCOW_OPEN_READ, &handle->error ) != 1 ) {
		logadd( LOG_ERROR, "Failed to open qcow2 file '%s'", filename );
		if ( handle->error != NULL ) {
			libqcow_error_free( &handle->error );
		}
		libqcow_file_free( &handle->qcow_file, NULL );
		free( handle );
		return NULL;
	}
	
	return handle;
}

void qcow2_close(qcow2_handle_t *handle)
{
	if ( handle == NULL ) {
		return;
	}
	
	if ( handle->qcow_file != NULL ) {
		libqcow_file_close( handle->qcow_file, NULL );
		libqcow_file_free( &handle->qcow_file, NULL );
	}
	
	if ( handle->error != NULL ) {
		libqcow_error_free( &handle->error );
	}
	
	free( handle );
}

uint64_t qcow2_get_size(qcow2_handle_t *handle)
{
	if ( handle == NULL || handle->qcow_file == NULL ) {
		return 0;
	}
	
	size64_t media_size = 0;
	if ( libqcow_file_get_media_size( handle->qcow_file, &media_size, &handle->error ) != 1 ) {
		logadd( LOG_ERROR, "Failed to get qcow2 media size" );
		if ( handle->error != NULL ) {
			libqcow_error_free( &handle->error );
			handle->error = NULL;
		}
		return 0;
	}
	
	return (uint64_t)media_size;
}

ssize_t qcow2_read(qcow2_handle_t *handle, void *buffer, size_t size, uint64_t offset)
{
	if ( handle == NULL || handle->qcow_file == NULL ) {
		return -1;
	}
	
	ssize_t bytes_read = libqcow_file_read_buffer_at_offset(
		handle->qcow_file,
		buffer,
		size,
		(off64_t)offset,
		&handle->error
	);
	
	if ( bytes_read < 0 ) {
		logadd( LOG_DEBUG1, "Failed to read from qcow2 file at offset %" PRIu64, offset );
		if ( handle->error != NULL ) {
			libqcow_error_free( &handle->error );
			handle->error = NULL;
		}
		return -1;
	}
	
	return bytes_read;
}
