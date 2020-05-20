#ifndef _JSON_RAISE_H
#define _JSON_RAISE_H

#include <json.h>

#define RAISE(RAISE)                                            \
    do                                                          \
    {                                                           \
        result = RAISE;                                         \
        goto done;                                              \
    }                                                           \
    while (0)

#define CHECK(RESULT)                                                   \
    do                                                                  \
    {                                                                   \
        json_result_t _r_ = RESULT;                                     \
        if (_r_ != JSON_OK)                                             \
        {                                                               \
            result = _r_;                                               \
            __json_trace_result(parser,                                 \
                __FILE__, __LINE__, __FUNCTION__, _r_);                 \
            goto done;                                                  \
        }                                                               \
    }                                                                   \
    while (0)

void __json_trace_result(
    json_parser_t* parser,
    const char* file,
    unsigned int line,
    const char* func,
    json_result_t result);

#endif /* _JSON_RAISE_H */
