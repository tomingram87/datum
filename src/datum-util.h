#ifndef DATUM_UTIL_H
#define DATUM_UTIL_H

/**
 * Enumeration of defined error codes.
 */
typedef enum {
    /** No error */
    DATUM_ERR_NONE = 0,

    /** argument was invalid (beyond invariants) */
    DATUM_ERR_INVALID_ARG,

    /** context is not in a valid state */
    DATUM_ERR_INVALID_STATE,

    /** out of memory */
    DATUM_ERR_NO_MEMORY,

} datum_errcode;

/**
 * An instance of an error context. Unlike other structures, it
 * is the API user's responsibility to allocate the structure; however
 * the values provided are considered constants, and MUST NOT be
 * deallocated.
 */
typedef struct
{
    /** The error code */
    datum_errcode code;

    /** The human readable message for the error code */
    const char *message;

    /** The function where the error occured, or "<unknown>"
        if it cannot be determined */
    const char *function;

    /** The file where the error occured */
    const char *file;

    /** The line number in the file where the error occured */
    unsigned long line;

} datum_err;

#endif /* DATUM_UTIL_H */
