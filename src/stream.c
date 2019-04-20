#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WINDOWS
#include <malloc.h>
#else
#include <alloca.h>
#endif

#include "stream.h"
#include "log.h"

#define align(n) (((n) | 3) + 1)

int stream_init(stream_t *stream)
{
	memset(stream, 0, sizeof(stream_t));
	return 0;
}

void stream_free(stream_t *stream)
{
	if (stream != NULL) {
		free(stream->array);
		memset(stream, 0, sizeof(stream_t));
	}
}

int stream_seek(stream_t *stream, int offset, int whence)
{
	switch (whence) {
	case SEEK_CUR:
		offset += stream->pos;
		break;
	case SEEK_END:
		offset = stream->size - offset;
		break;
	case SEEK_SET:
	default:
		break;
	}
	if (offset < 0 || offset > stream->size)
		return -1;
	stream->pos = offset;
	return 0;
}

int stream_set_cap(stream_t *stream, int cap)
{
	char *newarray;
	newarray = realloc(stream->array, cap);
	if (newarray == NULL)
		return -1;
	stream->array = newarray;
	stream->cap = cap;
	if (stream->size > cap)
		stream->size = cap;
	if (stream->pos > cap)
		stream->pos = cap;
	return 0;
}

int stream_write(stream_t *stream, const char *s, int n)
{
	if (stream_rcap(stream) < n) {
		if (stream_set_cap(stream, stream->pos + align(n)))
			return -1;
	}
	memcpy(stream->array + stream->pos, s, n);
	stream->pos += n;
	stream->size += n;
	return n;
}

int stream_writess(stream_t *dst, stream_t *src, int n)
{
	if (stream_rsize(src) < n)
		n = src->size - src->pos;

	if (stream_rcap(dst) < n) {
		if (stream_set_cap(dst, dst->pos + align(n)))
			return -1;
	}

	memcpy(dst->array + dst->pos, src->array + src->pos, n);
	dst->pos += n;
	dst->size += n;
	src->pos += n;
	return n;
}

int stream_read(stream_t *stream, char *dst, int n)
{
	if (stream_rsize(stream) < n)
		n = stream->size - stream->pos;
	memcpy(dst, stream->array + stream->pos, n);
	stream->pos += n;
	return n;
}

int stream_writei(stream_t *stream, int v, int nb)
{
	int i;
	if (stream_rcap(stream) < nb) {
		if (stream_set_cap(stream, stream->pos + align(nb)))
			return -1;
	}
	for (i = 0;
		i < nb && stream->size < stream->cap;
		i++, stream->size++) {
		stream->array[stream->pos++] = ((v >> ((nb - i - 1) * 8)) & 0xFF);
	}
	return i;
}

int stream_seti(stream_t *stream, int position, int v, int nb)
{
	int i;
	for (i = 0;
		i < nb && position < stream->cap;
		i++, position++) {
		stream->array[position] = ((v >> ((nb - i - 1) * 8)) & 0xFF);
	}
	return i;
}

int stream_vwritef(stream_t *stream, const char *fmt, va_list args)
{
	int cnt, sz;
	char *buf;
	va_list ap_try;

	sz = 128;
	buf = (char*)alloca(sz);
	if (!buf) return -1;
try_print:
	va_copy(ap_try, args);
	cnt = vsnprintf(buf, sz, fmt, ap_try);
	va_end(ap_try);
	if (cnt >= sz) {
		sz *= 2;
		buf = (char*)alloca(sz);
		if (!buf) return -1;
		goto try_print;
	}
	if (cnt < 0)
		return -1;

	if (stream_rcap(stream) < (cnt + 1)) {
		if (stream_set_cap(stream, stream->pos + align(cnt + 1)))
			return -1;
	}

	if (stream_write(stream, buf, cnt) != cnt) {
		return -1;
	}

	stream->array[stream->pos] = '\0';

	return cnt;
}

int stream_writef(stream_t *stream, const char *fmt, ...)
{
	int r;
	va_list args;
	va_start(args, fmt);
	r = stream_vwritef(stream, fmt, args);
	va_end(args);
	return r;
}

int stream_readi(stream_t *stream, int nb)
{
	int v = 0;
	int i;
	for (i = 0;
		i < nb && stream->pos < stream->size;
		i++, stream->pos++) {
		v <<= 8;
		v |= (stream->array[stream->pos] & 0xff);
	}
	return v;
}

static int get_ch(char *p, int i)
{
	int ch = p[i];
	ch &= 0xFF;
	if (ch == 32) ch = '.';
	else if (ch < 32 || ch > 126) ch = '?';
	return ch;
}

/* long-winded, but work */
void bprint(char *data, int len)
{
	int i;

	for (i = 0; i < len; i += 8) {
		switch (len - i) {
		case 1:
			logn("%04x: %02x                       %c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				get_ch(data, i + 0));
			break;
		case 2:
			logn("%04x: %02x %02x                    %c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1));
			break;
		case 3:
			logn("%04x: %02x %02x %02x                 %c%c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				(unsigned int)(data[i + 2] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1),
				get_ch(data, i + 2));
			break;
		case 4:
			logn("%04x: %02x %02x %02x %02x              %c%c%c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				(unsigned int)(data[i + 2] & 0xFF),
				(unsigned int)(data[i + 3] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1),
				get_ch(data, i + 2),
				get_ch(data, i + 3));
			break;
		case 5:
			logn("%04x: %02x %02x %02x %02x %02x           %c%c%c%c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				(unsigned int)(data[i + 2] & 0xFF),
				(unsigned int)(data[i + 3] & 0xFF),
				(unsigned int)(data[i + 4] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1),
				get_ch(data, i + 2),
				get_ch(data, i + 3),
				get_ch(data, i + 4));
			break;
		case 6:
			logn("%04x: %02x %02x %02x %02x %02x %02x        %c%c%c%c%c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				(unsigned int)(data[i + 2] & 0xFF),
				(unsigned int)(data[i + 3] & 0xFF),
				(unsigned int)(data[i + 4] & 0xFF),
				(unsigned int)(data[i + 5] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1),
				get_ch(data, i + 2),
				get_ch(data, i + 3),
				get_ch(data, i + 4),
				get_ch(data, i + 5));
			break;
		case 7:
			logn("%04x: %02x %02x %02x %02x %02x %02x %02x     %c%c%c%c%c%c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				(unsigned int)(data[i + 2] & 0xFF),
				(unsigned int)(data[i + 3] & 0xFF),
				(unsigned int)(data[i + 4] & 0xFF),
				(unsigned int)(data[i + 5] & 0xFF),
				(unsigned int)(data[i + 6] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1),
				get_ch(data, i + 2),
				get_ch(data, i + 3),
				get_ch(data, i + 4),
				get_ch(data, i + 5),
				get_ch(data, i + 6));
			break;
		default:
			logn("%04x: %02x %02x %02x %02x %02x %02x %02x %02x  %c%c%c%c%c%c%c%c\n", i,
				(unsigned int)(data[i + 0] & 0xFF),
				(unsigned int)(data[i + 1] & 0xFF),
				(unsigned int)(data[i + 2] & 0xFF),
				(unsigned int)(data[i + 3] & 0xFF),
				(unsigned int)(data[i + 4] & 0xFF),
				(unsigned int)(data[i + 5] & 0xFF),
				(unsigned int)(data[i + 6] & 0xFF),
				(unsigned int)(data[i + 7] & 0xFF),
				get_ch(data, i + 0),
				get_ch(data, i + 1),
				get_ch(data, i + 2),
				get_ch(data, i + 3),
				get_ch(data, i + 4),
				get_ch(data, i + 5),
				get_ch(data, i + 6),
				get_ch(data, i + 7));
			break;
		}
	}
}
