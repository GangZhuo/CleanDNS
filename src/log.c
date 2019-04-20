#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

log_vprintf_fun log_vprintf = log_default_vprintf;
log_vprintf_fun log_vprintf_with_timestamp = log_default_vprintf_with_timestamp;

static int s_log_level = LOG_DEFAULT_LEVEL;
static int s_log_flags = LOG_FLG_TIME;

static const char *prioritynames[] = {
	"emerg", "alert", "crit", "err", "warning", NULL /*notice*/,
	NULL /*info*/, "debug",
};

int *log_pflags()
{
	return &s_log_flags;
}

int *log_plevel()
{
	return &s_log_level;
}

void log_vwrite(int mask, const char *fmt, va_list args)
{
	if (log_level_comp(mask) <= loglevel) {
		if (mask & LOG_MASK_RAW) {
			log_vprintf(mask, fmt, args);
		}
		else if (s_log_flags & LOG_FLG_TIME) {
			log_vprintf_with_timestamp(mask, fmt, args);
		}
		else {
			log_vprintf(mask, fmt, args);
		}
	}
}

void log_write(int mask, const char *fmt, ...)
{
	if (log_level_comp(mask) <= loglevel) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(mask, fmt, args);
		va_end(args);
	}
}

const char* log_priorityname(int priority)
{
	if (priority >= 0 && priority < (sizeof(prioritynames) / sizeof(const char*)))
		return prioritynames[priority];
	
	return NULL;
}

static FILE *log_fp(int mask)
{
	FILE *pf;
	if (log_level_comp(mask) >= LOG_ERR)
		pf = stdout;
	else
		pf = stderr;
	return pf;
}

void log_default_vprintf(int mask, const char *fmt, va_list args)
{
	FILE *pf = log_fp(mask);
	vfprintf(pf, fmt, args);
	fflush(pf);
}

void log_default_vprintf_with_timestamp(int mask, const char *fmt, va_list args)
{
	char buf[640];
	int level = log_level_comp(mask);
	char date[32];
	const char *extra_msg;
	time_t now;
	FILE *pf = log_fp(mask);

	memset(buf, 0, sizeof(buf));
	vsnprintf(buf, sizeof(buf) - 1, fmt, args);

	now = time(NULL);

	strftime(date, sizeof(date), LOG_TIMEFORMAT, localtime(&now));
	extra_msg = log_priorityname(level);
	if (extra_msg && strlen(extra_msg)) {
		fprintf(pf, "%s [%s] %s", date, extra_msg, buf);
	}
	else {
		fprintf(pf, "%s %s", date, buf);
	}
	fflush(pf);
}
