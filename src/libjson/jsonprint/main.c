/*
**==============================================================================
**
** Copyright (c) Microsoft Corporation
**
** All rights reserved.
**
** MIT License
**
** Permission is hereby granted, free of charge, to any person obtaining a copy ** of this software and associated documentation files (the ""Software""), to 
** deal in the Software without restriction, including without limitation the 
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
** sell copies of the Software, and to permit persons to whom the Software is 
** furnished to do so, subject to the following conditions: The above copyright ** notice and this permission notice shall be included in all copies or 
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
#include <stdlib.h>
#include <ctype.h>
#include <json.h>
#include <sys/stat.h>
#include <string.h>

const char* arg0;

static const char* _reasons[] =
{
    "None",
    "Name",
    "BeginObject",
    "EndObject",
    "BeginArray",
    "EndArray",
    "Value"
};

static const char* _types[] =
{
    "Null",
    "Boolean",
    "Integer",
    "Real",
    "String"
};

typedef struct _CallbackData
{
    int depth;
    int newline;
    int comma;
}
CallbackData;

static void _PrintString(const char* str)
{
    printf("\"");

    while (*str)
    {
        char c = *str++;

        switch (c)
        {
            case '"':
                printf("\\\"");
                break;
            case '\\':
                printf("\\\\");
                break;
            case '\b':
                printf("\\b");
                break;
            case '\f':
                printf("\\f");
                break;
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            default:
            {
                if (isprint(c))
                    printf("%c", c);
                else
                    printf("\\u%04X", c);
            }
        }
    }

    printf("\"");
}

static void _PrintValue(json_type_t type, const json_union_t* value)
{
    switch (type)
    {
        case JSON_TYPE_NULL:
            printf("null");
            break;
        case JSON_TYPE_BOOLEAN:
            printf("%s", value->boolean ? "true" : "false");
            break;
        case JSON_TYPE_INTEGER:
            printf("%lld", value->integer);
            break;
        case JSON_TYPE_REAL:
            printf("%E", value->real);
            break;
        case JSON_TYPE_STRING:
#if 1
            _PrintString(value->string);
#else
            printf("\"%s\"", value->u.string);
            (void)_PrintString;
#endif
            break;
        default:
            break;
    }
}

void DumpCallbackParameters(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* value,
    void* callbackData)
{
    printf("reason{%s}\n", _reasons[reason]);

    if (reason == JSON_REASON_VALUE)
    {
        printf("type{%s}\n", _types[type]);
        printf("value{");
        _PrintValue(type, value);
        printf("}\n");
    }
}

static void _Indent(int depth)
{
    size_t i;

    for (i = 0; i < depth; i++)
        printf("  ");
}

json_result_t _Callback(
    json_parser_t* parser,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un,
    void* callbackData)
{
    CallbackData* data = (CallbackData*)callbackData;

    /* Print commas */
    if (reason != JSON_REASON_END_ARRAY &&
        reason != JSON_REASON_END_OBJECT &&
        data->comma)
    {
        data->comma = 0;
        printf(",");
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
        printf("\n");
        _Indent(data->depth);
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
            _PrintString(un->string);
            printf(": ");
            data->comma = 0;
            break;
        }
        case JSON_REASON_BEGIN_OBJECT:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            printf("{");
            break;
        }
        case JSON_REASON_END_OBJECT:
        {
            data->newline = 1;
            data->comma = 1;
            printf("}");
            break;
        }
        case JSON_REASON_BEGIN_ARRAY:
        {
            data->depth++;
            data->newline = 1;
            data->comma = 0;
            printf("[");
            break;
        }
        case JSON_REASON_END_ARRAY:
        {
            data->newline = 1;
            data->comma = 1;
            printf("]");
            break;
        }
        case JSON_REASON_VALUE:
        {
            data->newline = 1;
            data->comma = 1;
            _PrintValue(type, un);
            break;
        }
    }

    /* Final newline */
    if (reason == JSON_REASON_END_OBJECT ||
        reason == JSON_REASON_END_ARRAY)
    {
        if (data->depth == 0)
            printf("\n");
    }

    return JSON_OK;
}

int _load_file(
    const char* path,
    size_t extra_bytes,
    void** data_out,
    size_t* size_out)
{
    int ret = -1;
    FILE* is = NULL;
    void* data = NULL;
    size_t size;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        size = (size_t)st.st_size;
    }

    /* Allocate memory */
    if (!(data = malloc(size + extra_bytes)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    /* Zero-fill any extra bytes */
    if (extra_bytes)
        memset((unsigned char*)data + size, 0, extra_bytes);

    *data_out = data;
    *size_out = size;
    data = NULL;

    ret = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return ret;
}

static void _parse(const char* path)
{
    json_parser_t parser;
    char* data;
    size_t size;
    json_result_t r;
    CallbackData callbackData;
    static json_allocator_t allocator =
    {
        malloc,
        free,
    };

    callbackData.depth = 0;
    callbackData.newline = 0;
    callbackData.comma = 0;

    if (_load_file(path, 1, (void**)&data, &size) != 0)
    {
        fprintf(stderr, "%s: failed to access '%s'\n", arg0, path);
        exit(1);
    }

    if ((r = json_parser_init(&parser, data, size, _Callback,
        &callbackData, &allocator)) != JSON_OK)
    {
        fprintf(stderr, "%s: json_parser_init() failed: %d\n", arg0, r);
        exit(1);
    }

    if ((r = json_parser_parse(&parser)) != JSON_OK)
    {
        fprintf(stderr, "%s: json_parser_parse() failed: %d\n", arg0, r);
        exit(1);
    }

    if (callbackData.depth != 0)
    {
        fprintf(stderr, "%s: unterminated objects\n", arg0);
        exit(1);
    }
}

int main(int argc, char** argv)
{
    arg0 = argv[0];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s path\n", argv[0]);
        exit(1);
    }

    _parse(argv[1]);

    return 0;
}
