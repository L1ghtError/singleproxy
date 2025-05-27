#ifndef _STATUS_H_
#define _STATUS_H_

static const char *code_desc[] = {"Ok", "Invalid input", "Aborted", "Not Found", "Data Malformed"};

enum ret_code { kOk = 0, kInvalidInput = 1, kAborted = 2, kNotFound = 3, kDataMalformed = 4 };

typedef enum ret_code dns_rc_t;
#endif // _STATUS_H_
