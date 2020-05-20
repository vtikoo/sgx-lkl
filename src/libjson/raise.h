/*
**==============================================================================
**
** Copyright (c) Microsoft Corporation
**
** All rights reserved.
**
** MIT License
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the ""Software""), to
** deal in the Software without restriction, including without limitation the
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
** sell copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions: The above copyright
** notice and this permission notice shall be included in all copies or
** substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
**==============================================================================
*/

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
