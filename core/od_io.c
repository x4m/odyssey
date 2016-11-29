
/*
 * odissey.
 *
 * PostgreSQL connection pooler and request router.
*/

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <machinarium.h>
#include <soprano.h>

#include "od_macro.h"
#include "od_pid.h"
#include "od_syslog.h"
#include "od_log.h"
#include "od_io.h"

int od_read(mm_io_t *io, so_stream_t *stream, int time_ms)
{
	so_stream_reset(stream);
	for (;;) {
		uint32_t pos_size = so_stream_used(stream);
		uint8_t *pos_data = stream->s;
		uint32_t len;
		int to_read;
		to_read = so_read(&len, &pos_data, &pos_size);
		if (to_read == 0)
			break;
		if (to_read == -1)
			return -1;
		int rc = so_stream_ensure(stream, to_read);
		if (rc == -1)
			return -1;
		rc = mm_read(io, to_read, time_ms);
		if (rc < 0)
			return -1;
		char *data_pointer = mm_read_buf(io);
		memcpy(stream->p, data_pointer, to_read);
		so_stream_advance(stream, to_read);
	}
	return 0;
}

int od_write(mm_io_t *io, so_stream_t *stream)
{
	int rc;
	rc = mm_write(io, (char*)stream->s, so_stream_used(stream), 0);
	if (rc < 0)
		return -1;
	return 0;
}