#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

int daemon_proc;
int debug_level = 2;

static void err_doit(int, int, const char *, va_list);

#ifndef MAXLINE
#define MAXLINE 4096
#endif

/**
 * @fn void debug_msg(const char *format, ...)
 * Prints the message to STDERR if DEBUG is #defined
 * @param format The format of the msg (see printf manpage)
 * @param ... Optional arguments
 */

void debug_msg(const char *format, ...)
{
    if (debug_level > 1 && format) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }
    return;
}

void
set_debug_msg_level(int level) {
    debug_level = level;
    return;
}

int
get_debug_msg_level() {
    return debug_level;
}

void
err_ret(const char *fmt, ...) {
    va_list ap;

    va_start (ap, fmt);
    err_doit(1, LOG_INFO, fmt, ap);
    va_end (ap);
    return;
}

/**
 * @fn void err_msg (const char *fmt, ...)
 * Print a message and return. Nonfatal error unrelated to a system call.
 * @param fmt Format string the same as printf function
 * @param ... Arguments for the format string
 */
void
err_msg(const char *fmt, ...) {
    va_list ap;

    va_start (ap, fmt);
    err_doit(0, LOG_INFO, fmt, ap);
    va_end (ap);
    return;
}

/**
 * @fn void err_quit (const char *fmt, ...)
 * Print a message and terminate. Fatal error unrelated to a system call.
 * @param fmt Format string the same as printf function
 * @param ... Arguments for the format string
 */
void
err_quit(const char *fmt, ...) {
    va_list ap;

    va_start (ap, fmt);
    err_doit(0, LOG_ERR, fmt, ap);
    va_end (ap);
    exit(1);
}

/* Print a message and return to caller.
 * Caller specifies "errnoflag" and "level". */

static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap) {
    int errno_save, n;
    char buf[MAXLINE + 1];

    errno_save = errno;        /* value caller might want printed */
#ifdef    HAVE_VSNPRINTF
    vsnprintf (buf, MAXLINE, fmt, ap);	/* safe */
#else
    vsprintf(buf, fmt, ap);    /* not safe */
#endif
    n = strlen(buf);
    if (errnoflag)
        snprintf(buf + n, MAXLINE - n, ": %s", strerror(errno_save));
#ifdef HAVE_STRLCAT
    strlcat (buf, "\n", MAXLINE);
#else
    strcat(buf, "\n");
#endif

    if (daemon_proc) {
        syslog(level, "%s", buf);
    } else {
        fflush(stdout);    /* in case stdout and stderr are the same */
        fputs(buf, stderr);
        fflush(stderr);
    }
    return;
}

