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

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "jsonprint.h"
#include "raise.h"

static void _Indent(FILE* os, size_t depth)
{
    size_t i;

    for (i = 0; i < depth; i++)
        fprintf(os, "  ");
}

static void _PrintString(FILE* os, const char* str)
{
    fprintf(os, "\"");

    while (*str)
    {
        char c = *str++;

        switch (c)
        {
            case '"':
                fprintf(os, "\\\"");
                break;
            case '\\':
                fprintf(os, "\\\\");
                break;
            case '/':
                fprintf(os, "\\/");
                break;
            case '\b':
                fprintf(os, "\\b");
                break;
            case '\f':
                fprintf(os, "\\f");
                break;
            case '\n':
                fprintf(os, "\\n");
                break;
            case '\r':
                fprintf(os, "\\r");
                break;
            case '\t':
                fprintf(os, "\\t");
                break;
            default:
            {
                if (isprint(c))
                    fprintf(os, "%c", c);
                else
                    fprintf(os, "\\u%04X", c);
            }
        }
    }

    fprintf(os, "\"");
}

void json_print_value(FILE* os, json_type_t type, const json_union_t* un)
{
    switch (type)
    {
        case JSON_TYPE_NULL:
            fprintf(os, "null");
            break;
        case JSON_TYPE_BOOLEAN:
            fprintf(os, "%s", un->boolean ? "true" : "false");
            break;
        case JSON_TYPE_INTEGER:
            fprintf(os, "%lld", un->integer);
            break;
        case JSON_TYPE_REAL:
            fprintf(os, "%E", un->real);
            break;
        case JSON_TYPE_STRING:
            _PrintString(os, un->string);
            break;
        default:
            break;
    }
}

typedef struct callback_data
{
    int depth;
    int newline;
    int comma;
    FILE* os;
}
callback_data_t;

json_result_t _json_print_callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callback_data)
{
    callback_data_t* data = callback_data;
    FILE* os = data->os;

    (void)parser;

    /* Print commas */
    if (reason != JSON_REASON_END_ARRAY &&
        reason != JSON_REASON_END_OBJECT &&
        data->comma)
    {
        data->comma = 0;
        fprintf(os, ",");
    }

    /* Decrease depth */
    if (reason == JSON_REASON_END_OBJECT ||
        reason == JSON_REASON_END_ARRAY)
    {
        data->depth--;
    }

    /* Print newline */
    if (data->newline)
    {
        data->newline = 0;
        fprintf(os, "\n");
        _Indent(os, data->depth);
    }

    switch (reason)
    {
        case JSON_REASON_NONE:
        {
            /* Unreachable */
            break;
        }
        case JSON_REASON_NAME:
        {
            _PrintString(os, un->string);
            fprintf(os, ": ");
            data->comma = 0;
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            fprintf(os, "{");
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            data->newline = 1;
            data->comma = 1;
            fprintf(os, "}");
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            fprintf(os, "[");
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            data->newline = 1;
            data->comma = 1;
            fprintf(os, "]");
            break;
        }
        case JSON_REASON_VALUE:
        {
            data->newline = 1;
            data->comma = 1;
            json_print_value(os, type, un);
            break;
        }
    }

    /* Final newline */
    if (reason == JSON_REASON_END_OBJECT ||
        reason == JSON_REASON_END_ARRAY)
    {
        if (data->depth == 0)
            fprintf(os, "\n");
    }

    return JSON_OK;
}

json_result_t json_print(
    FILE* os,
    const char* json_data,
    size_t json_size)
{
    json_result_t result = JSON_UNEXPECTED;
    char* data = NULL;
    json_parser_t parser;
    callback_data_t callback_data = { 0, 0, 0, os };
    static json_allocator_t allocator =
    {
        malloc,
        free,
    };

    if (!json_data || !json_size)
        RAISE(JSON_BAD_PARAMETER);

    if (!(data = malloc(json_size)))
        RAISE(JSON_OUT_OF_MEMORY);

    memcpy(data, json_data, json_size);

    if (json_parser_init(
        &parser,
        data,
        json_size,
        _json_print_callback,
        &callback_data,
        &allocator) != JSON_OK)
    {
        RAISE(JSON_FAILED);
    }

    if (json_parser_parse(&parser) != JSON_OK)
    {
        RAISE(JSON_BAD_SYNTAX);
    }

    if (callback_data.depth != 0)
    {
        RAISE(JSON_BAD_SYNTAX);
    }

    result = JSON_OK;

done:

    if (data)
        free(data);

    return result;
}

void json_dump_path(const char* path[], size_t depth)
{
    if (path)
    {
        for (size_t i = 0; i < depth; i++)
        {
            printf("%s", path[i]);

            if (i + 1 != depth)
                printf(".");
        }

        printf("\n");
    }
}
