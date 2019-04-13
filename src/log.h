#ifndef CLEANDNS_LOG_H_
#define CLEANDNS_LOG_H_

#include <stdarg.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* priorities (same syslog.h) */
#define	LOG_EMERG		0	/* system is unusable */
#define	LOG_ALERT		1	/* action must be taken immediately */
#define	LOG_CRIT		2	/* critical conditions */
#define	LOG_ERR			3	/* error conditions */
#define	LOG_WARNING		4	/* warning conditions */
#define	LOG_NOTICE		5	/* normal but significant condition */
#define	LOG_INFO		6	/* informational */
#define	LOG_DEBUG		7	/* debug-level messages */

#define LOG_FLG_TIME	(1 << 0) /* log with timestamp */

#define LOG_MASK_RAW	(1 << 8) /* log raw message */

typedef void (*log_vprintf_fun)(int mask, const char* fmt, va_list args);

extern log_vprintf_fun log_vprintf;
extern log_vprintf_fun log_vprintf_with_timestamp;

int *log_pflags();
int *log_plevel();

void log_write(int mask, const char *fmt, ...);
void log_vwrite(int mask, const char *fmt, va_list args);
void log_default_vprintf(int mask, const char* fmt, va_list args);
void log_default_vprintf_with_timestamp(int mask, const char* fmt, va_list args);

#define loglevel (*(log_plevel()))
#define logflags (*(log_pflags()))

#define log_level_comp(mask) ((mask) & 0xFF)

static inline void logc(const char *fmt, ...)
{
	if (loglevel >= LOG_CRIT) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(LOG_CRIT, fmt, args);
		va_end(args);
	}
	exit(-1);
}

static inline void loge(const char *fmt, ...)
{
	if (loglevel >= LOG_ERR) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(LOG_ERR, fmt, args);
		va_end(args);
	}
}

static inline void logw(const char *fmt, ...)
{
	if (loglevel >= LOG_WARNING) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(LOG_WARNING, fmt, args);
		va_end(args);
	}
}

static inline void logn(const char *fmt, ...)
{
	if (loglevel >= LOG_NOTICE) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(LOG_NOTICE, fmt, args);
		va_end(args);
	}
}

static inline void logi(const char *fmt, ...)
{
	if (loglevel >= LOG_INFO) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(LOG_INFO, fmt, args);
		va_end(args);
	}
}

static inline void logd(const char *fmt, ...)
{
	if (loglevel >= LOG_DEBUG) {
		va_list args;
		va_start(args, fmt);
		log_vwrite(LOG_DEBUG, fmt, args);
		va_end(args);
	}
}

#ifdef __cplusplus
}
#endif

#endif /*CLEANDNS_LOG_H_*/
