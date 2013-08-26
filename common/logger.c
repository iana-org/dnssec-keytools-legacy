/*
 * $Id: logger.c 359 2010-05-28 21:43:18Z jakob $
 *
 * Copyright (C) 2010 Internet Corporation for Assigned Names
 *                    and Numbers (ICANN)
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ICANN+RHL DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ICANN+RHL BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <syslog.h>
#include <time.h>

#include "logger.h"

#define TIMESTAMP_LENGTH 64
#define LOGENTRY_LENGTH  1024
#define CTIME_LENGTH 26

static int log_flags = 0;
static int log_initialized = 0;
static FILE *log_fp = NULL;

static const char *logfile_timeformat = "%Y%m%d-%H%M%S";
static const char *logentry_timeformat = "%Y-%m-%dT%H:%M:%SZ";
static char logfile_fname[MAXPATHLEN];

static void
internal_fatal(const char *message)
{
  if(message == NULL) {
    fprintf(stderr,"FATAL: Failed to write to logfile %s (errno=%d, %s)\n",
            logfile_fname, errno, strerror(errno));
  } else {
    fprintf(stderr,"FATAL: %s (errno=%d, %s)\n",
            message, errno, strerror(errno));
  }

  fprintf(stderr,"FATAL: Program will be terminated.\n");

  exit(-1);
}

static const char *pri2str(int pri)
{
  if (pri == LOG_EMERG)   return "emergency";
  if (pri == LOG_ALERT)   return "alert";
  if (pri == LOG_CRIT)    return "critical";
  if (pri == LOG_ERR)     return "error";
  if (pri == LOG_WARNING) return "waring";
  if (pri == LOG_NOTICE)  return "notice";
  if (pri == LOG_INFO)    return "info";
  if (pri == LOG_DEBUG)   return "debug";
  
  return "unknown";
}

static void logger_atexit()
{
  const char *separator = "**********";

  fprintf(stderr, "\n");
  fprintf(stderr, "%s Log output in %s %s\n",
          separator, logger_filename(), separator);
}


/*
 * Initialize logger
 *
 * Log output will be written to a file beginning with [basename]
 * in [dir]. Output filename will include a timestamp.
 * The [flags] are used to select if the log output is also
 * mirrored on STDOUT and, if so, those log entries are prepended with a
 * a timestamp.
 */
int logger_init(const char *basename, const char *dir, int flags)
{
  char tstamp[TIMESTAMP_LENGTH];
  time_t now;

  now = time(NULL);

  if (basename == NULL) return -1;
  if (dir == NULL) return -1;
  if (log_initialized) return 0;

  log_flags = flags;

  if (!strftime(tstamp, sizeof(tstamp), logfile_timeformat, gmtime(&now))) {
    return -1;
  }

  if (!snprintf(logfile_fname, sizeof(logfile_fname),
                "%s/%s-%s.log", dir, basename, tstamp)) {
    return -1;
  }

  /* Open logfile for append, fail if unsuccessful */
  log_fp = fopen(logfile_fname, "a");
  if (log_fp == NULL) internal_fatal(NULL);

  atexit(logger_atexit);

  log_initialized = 1;

  return 0;
}

void logger_close()
{
  if (log_fp) fclose(log_fp);
  log_initialized = 0; 
}

void logger_stdout_enable()
{
  log_flags |= LOG_STDOUT;
}

void logger_stdout_disable()
{
  log_flags &= ~LOG_STDOUT;  
}

const char *logger_filename()
{
  return logfile_fname;
}

static void logger_vmessage(int pri, const char *format, va_list ap)
{
  static char tstamp[TIMESTAMP_LENGTH];

  time_t now;
  va_list ap1, ap2;

  if (!log_initialized) internal_fatal("Logger not initialized");

  /* Create & fill timestamp */
  now = time(NULL);
  strftime(tstamp, sizeof(tstamp), logentry_timeformat, gmtime(&now));

  /* Log to STDOUT if requested */
  if((log_flags & LOG_STDOUT)) {

    /* Optionally include timestamp on STDOUT */
    if((log_flags & LOG_TIMESTAMP)) {
      fprintf(stdout, "%s: ", tstamp);
    }
    
    /* Prefix all non-information message with [priority] */
    if (pri != LOG_INFO) {
      fprintf(stdout, "[%s] ", pri2str(pri));
    }

    va_copy(ap1, ap);
    vfprintf(stdout, format, ap1);
    va_end(ap1);
    fprintf(stdout, "\n");
  }

  /* Log to FILE */
  fprintf(log_fp, "%s: [%s] ", tstamp, pri2str(pri));
  va_copy(ap2, ap);
  vfprintf(log_fp, format, ap2);
  va_end(ap2);
  fprintf(log_fp, "\n");

  /* Flush output */
  if(fflush(log_fp)) internal_fatal(NULL);
}

/*
 * syslog(3)-like logger
 */
void logger_message(int pri, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(pri, format, ap);
  va_end(ap);
}

/*
 * syslog(3)-like logger with exit(-1)
 */
void logger_fatal(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(LOG_ERR, format, ap);
  va_end(ap);

  exit(-1);
}

void logger_debug(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(LOG_DEBUG, format, ap);
  va_end(ap);
}

void logger_info(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(LOG_INFO, format, ap);
  va_end(ap);
}

void logger_notice(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(LOG_NOTICE, format, ap);
  va_end(ap);
}

void logger_warning(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(LOG_WARNING, format, ap);
  va_end(ap);
}

void logger_error(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  logger_vmessage(LOG_ERR, format, ap);
  va_end(ap);
}


/*
 * Dump program startup message
 */
void logger_hello(int argc, char *argv[])
{
  char lbuf[1024];
  int n = 0, i;
  time_t now;
  char nowstr[CTIME_LENGTH];

  /* FIXME: report error on overflow? */

  n = snprintf(lbuf+n, sizeof(lbuf)-n, "Starting:");

  for(i=0; i<argc; i++) {
    n += snprintf(lbuf+n, sizeof(lbuf)-n, " %s", argv[i]);
  }

  time(&now);
  ctime_r(&now, nowstr);
  nowstr[24] = '\0'; /* remove trailing linefeed */

  n += snprintf(lbuf+n, sizeof(lbuf)-n, " (at %s %s)",
    nowstr, daylight?tzname[0]:tzname[1]);

  logger_message(LOG_INFO, "%s", lbuf);
}

/* Legacy logger, will be removed eventually */
void myx_syslog(int pri,const char *format, ...)
{
  static char ts[TIMESTAMP_LENGTH];
  static char logentry[LOGENTRY_LENGTH];

  va_list args;
  time_t now;

  if (!log_initialized) internal_fatal("Logger not initialized");

  {
    char *p;
    static char tsentry[TIMESTAMP_LENGTH];
    static int qcrlf=0;

    /* FOOP - I use this for direct CGI output as well so have to turn off */
    /* Log to STDOUT if applicable - No timestamps to make it readable */
    if((log_flags & LOG_STDOUT)) {
      va_start(args,format);
      vsnprintf(logentry, LOGENTRY_LENGTH, format, args);
      va_end(args);
      fprintf(stdout, "%s", logentry);
    }

    va_start(args,format);
    vsnprintf(logentry, LOGENTRY_LENGTH, format, args);
    va_end(args);

    for(p=logentry;*p;p++) {
      if(qcrlf == 0) {
        /* Create & fill timestamp & log to file and flush */
        now = time(NULL);
        strftime(ts, sizeof(ts), logentry_timeformat, gmtime(&now));
        snprintf(tsentry, sizeof(tsentry), "%s: [%s] ", ts, pri2str(pri));
        qcrlf = 1;
        fprintf(log_fp, "%s", tsentry);
      }
      fprintf(log_fp,"%c",*p);
      if(*p == '\n') qcrlf = 0;
    }
    if(fflush(log_fp)) internal_fatal(NULL);
  }
}
