/*
 * $Id: logger.h 567 2010-10-28 05:11:10Z jakob $
 *
 * Copyright (c) 2010 Internet Corporation for Assigned Names ("ICANN")
 * 
 * Author: Richard H. Lamb ("RHL") richard.lamb@icann.org
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <stdarg.h>


#define LOG_EMPTY     0x00000000    /*!< No log flags */
#define LOG_STDOUT    0x00000001    /*!< Log to STDOUT */
#define LOG_TIMESTAMP 0x00000002    /*!< Include timestamp on STDOUT */

#define myx_openlog(b,d,f) logger_init(b,d,f)  /*!< compat */

int logger_init(const char *basename, const char *dir, int flags);
void logger_close();

void logger_stdout_enable();
void logger_stdout_disable();

const char *logger_filename();
void logger_hello(int argc, char *argv[]);
void logger_message(int pri, const char *format, ...);

void logger_fatal(const char *format, ...);

void logger_debug(const char *format, ...);
void logger_info(const char *format, ...);
void logger_notice(const char *format, ...);
void logger_warning(const char *format, ...);
void logger_error(const char *format, ...);

void myx_syslog(int pri, const char *format, ...);

#endif /* _LOGGER_H_ */
