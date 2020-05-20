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

#include "json.h"
#include "raise.h"

/*
**==============================================================================
**
** libc compatibility:
**
**==============================================================================
*/

typedef _Bool bool;

#define false ((bool)0)
#define true ((bool)1)

#ifndef NULL
#define NULL ((void*)0)
#endif

#define UINT64_MAX (0xffffffffffffffffu)
#define LONG_MAX 0x7fffffffffffffffL
#define ULONG_MAX (2UL * LONG_MAX + 1)

typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef long ptrdiff_t;
typedef unsigned long size_t;
typedef unsigned int uint32_t;

static int _tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? (c - ' ') : c;
}

static int _isdigit(int c)
{
    return (c >= '0' && c <= '9');
}

static int _isspace(int c)
{
    return c == ' ' || c == '\f' || c == '\n' ||
        c == '\r' || c == '\t' || c == '\v';
}

static void* _memset(void* s, int c, size_t n)
{
    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = c;

    return s;
}

static void* _memcpy(void* dest, const void* src, size_t n)
{
    unsigned char* p = (unsigned char*)dest;
    unsigned char* q = (unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;
}

static int _memcmp(const void* s1, const void* s2, size_t n)
{
    unsigned char* p = (unsigned char*)s1;
    unsigned char* q = (unsigned char*)s2;

    while (n--)
    {
        if (*p < *q)
            return -1;
        else if (*p > *q)
            return 1;

        p++;
        q++;
    }

    return 0;
}

static void* _memmove(void* dest_, const void* src_, size_t n)
{
    char *dest = (char*)dest_;
    const char *src = (const char*)src_;

    if (dest != src && n > 0)
    {
        if (dest <= src)
        {
            _memcpy(dest, src, n);
        }
        else
        {
            for (src += n, dest += n; n--; dest--, src--)
                dest[-1] = src[-1];
        }
    }

    return dest;
}

static size_t _strlen(const char* s)
{
    const char* p = (const char*)s;

    while (*p++)
        ;

    return p - s;
}

static int _strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

static char* _strcpy(char* dest, const char* src)
{
    char* ret = dest;

    while (*src)
        *dest++ = *src++;

    *dest = '\0';

    return ret;
}

static char* _strchr(const char* s, int c)
{
    while (*s && *s != c)
        s++;

    if (*s == c)
        return (char*)s;

    return NULL;
}

static size_t _strspn(const char* s, const char* accept)
{
    const char* p = s;

    while (*p)
    {
        if (!_strchr(accept, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

static size_t _strcspn(const char* s, const char* reject)
{
    const char* p = s;

    while (*p)
    {
        if (_strchr(reject, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

//
// If c is a digit character:
//     then: _digit[c] yields the integer value for that digit character.
//     else: _digit[c] yields 0xFF.
//
// Digit characters fall within these ranges: ['0'-'9'] and ['A'-'Z'].
//
// Examples:
//     _digit['9'] => 9
//     _digit['A'] => 10
//     _digit['Z'] => 35
//     _digit['?'] => 0xFF
//
static const unsigned char _digit[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
};

/* Return true if c is a digit character with the given base */
static bool _isdigit2(char c, int base)
{
    return _digit[(unsigned char)c] < base;
}

static long int _strtol(const char* nptr, char** endptr, int base)
{
    const char* p;
    unsigned long x = 0;
    bool negative = false;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr || base < 0)
        return 0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = true;
        p++;
    }

    /* If base is zero, deduce the base from the prefix. */
    if (base == 0)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            base = 16;
        }
        else if (p[0] == '0')
        {
            base = 8;
        }
        else
        {
            base = 10;
        }
    }

    /* Remove any base 16 prefix. */
    if (base == 16)
    {
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        {
            p += 2;
        }
    }

    /* Remove any base 8 prefix. */
    if (base == 8)
    {
        if (p[0] == '0')
        {
            p++;
        }
    }

    for (; *p && _isdigit2(*p, base); p++)
    {
        /* Multiply by base */
        {
            /* Check for overflow */
            if (x > UINT64_MAX / (unsigned long)base)
            {
                if (endptr)
                    *endptr = (char*)p;

                return UINT64_MAX;
            }

            x = x * (unsigned long)base;
        }

        /* Add digit */
        {
            const unsigned long digit = _digit[(unsigned char)*p];

            /* Check for overflow */
            if (digit > ULONG_MAX - x)
            {
                if (endptr)
                    *endptr = (char*)p;

                return UINT64_MAX;
            }

            x += digit;
        }
    }

    /* Return zero if no digits were found */
    if (p == nptr)
        return 0;

    if (endptr)
        *endptr = (char*)p;

    /* Invert if negative */
    if (negative)
    {
        if (x > LONG_MAX)
        {
            if (x == (unsigned long)LONG_MAX + 1)
                return x;
            else
                return 0;
        }
        x = (unsigned long)-(long)x;
    }

    return (long)x;
}

static unsigned long int _strtoul(const char* nptr, char** endptr, int base)
{
    return (unsigned long)_strtol(nptr, endptr, base);
}

static double _strtod(const char* nptr, char** endptr)
{
    const char* p;
    bool negative = false;
    bool exp_negative = false;
    unsigned long x;
    unsigned long y = 0;
    unsigned long r = 1;
    unsigned long exp = 0;
    bool have_x = false;
    double z;

    if (endptr)
        *endptr = (char*)nptr;

    if (!nptr)
        return 0.0;

    /* Set scanning pointer to nptr */
    p = nptr;

    /* Skip any leading whitespace */
    while (_isspace(*p))
        p++;

    /* Handle '+' and '-' */
    if (p[0] == '+')
    {
        p++;
    }
    else if (p[0] == '-')
    {
        negative = true;
        p++;
    }

    /* Parse the leading number */
    {
        char* end;
        x = _strtoul(p, &end, 10);

        if (p != end)
        {
            have_x = true;
            *endptr = (char*)end;
        }

        p = end;
    }

    /* Parse the decimal and trailing number */
    if (*p == '.')
    {
        char* end;

        p++;
        y = _strtoul(p, &end, 10);

        if (p != end)
        {
            size_t n;
            *endptr = (char*)end;

            /* Calculate the number of decimal places */
            n = end - p;
            p = end;

            /* Find a divisor */
            while (n--)
                r *= 10;
        }
        else if (have_x)
        {
            *endptr = (char*)p;
        }
        else
        {
            *endptr = (char*)(p - 1);
            return 0.0;
        }
    }

    /* Handle exponent if any */
    if (*p == 'e' || *p == 'E')
    {
        char* end;
        p++;

        if (*p == '-')
            exp_negative = true;

        if (*p == '-' || *p == '+')
            p++;

        exp = _strtoul(p, &end, 10);

        if (p != end)
            *endptr = (char*)end;

        p = end;
    }

    z = (double)x + ((double)y / (double)r);

    if (exp)
    {
        for (size_t i = 0; i < exp; i++)
        {
            if (exp_negative)
                z /= 10;
            else
                z *= 10;
        }
    }

    return negative ? -z : z;
}

/*
**==============================================================================
**
** JSON paraser implementation:
**
**==============================================================================
*/

#define JSON_STRLIT(STR) STR, sizeof(STR)-1

#define RETURN(VALUE)                                                       \
    do                                                                      \
    {                                                                       \
        return VALUE;                                                       \
    }                                                                       \
    while (0)

static size_t _split(
    char* str,
    const char* delim,
    const char* tokens[],
    size_t ntokens)
{
    char* p = (char*)str;
    size_t i = 0;

    for (;;)
    {
        /* Skip leading delimiting characters */
        p += _strspn(p, delim);

        /* Terminate if at end of string */
        if (!*p)
            break;

        /* Check for overflow */
        if (i == ntokens)
            return (size_t)-1;

        /* Add token to the array */
        tokens[i++] = p;

        /* Skip over non-delimiting characters */
        p += _strcspn(p, delim);

        if (!*p)
            break;

        *p++ = '\0';
    }

    if (*p)
        return (size_t)-1;

    return i;
}

static unsigned char _CharToHexNibble(char c)
{
    c = _tolower(c);

    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return 0xa + (c - 'a');

    return 0xFF;
}

static int _IsNumberChar(char c)
{
    return
        _isdigit(c) || c == '-' || c == '+' || c == 'e' || c == 'E' || c == '.';
}

static int _IsDecimalOrExponent(char c)
{
    return c == '.' || c == 'e' || c == 'E';
}

static int _HexStr4ToUint(const char* s, unsigned int* x)
{
    unsigned int n0 = _CharToHexNibble(s[0]);
    unsigned int n1 = _CharToHexNibble(s[1]);
    unsigned int n2 = _CharToHexNibble(s[2]);
    unsigned int n3 = _CharToHexNibble(s[3]);

    if ((n0 | n1 | n2 | n3) & 0xF0)
        return -1;

    *x = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
    return 0;
}

static json_result_t _invoke_callback(
    json_parser_t* self,
    json_reason_t reason,
    json_type_t type,
    const json_union_t* un)
{
    return self->callback(self, reason, type, un, self->callback_data);
}

static json_result_t _GetString(json_parser_t* self, char** str)
{
    char* start = self->ptr;
    char* p = start;
    const char* end = self->end;
    int escaped = 0;

    /* Save the start of the string */
    *str = p;

    /* Find the closing quote */
    while (p != end && *p != '"')
    {
        if (*p++ == '\\')
        {
            escaped = 1;

            if (*p == 'u')
            {
                if (end - p < 4)
                    RETURN(JSON_EOF);
                p += 4;
            }
            else
            {
                if (p == end)
                    RETURN(JSON_EOF);
                p++;
            }
        }
    }

    if (p == end || *p != '"')
        RETURN(JSON_EOF);

    /* Update the os */
    self->ptr += p - start + 1;

    /* Overwrite the '"' character */
    *p = '\0';
    end = p;

    /* ATTN.B: store length (end-p) to str[-1] */

    /* Process escaped characters (if any) */
    if (escaped)
    {
        p = start;

        while (*p)
        {
            /* Handled escaped characters */
            if (*p == '\\')
            {
                p++;

                if (!*p)
                    RETURN(JSON_EOF);

                switch (*p)
                {
                    case '"':
                        p[-1] = '"';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case '\\':
                        p[-1] = '\\';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case '/':
                        p[-1] = '/';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'b':
                        p[-1] = '\b';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'f':
                        p[-1] = '\f';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'n':
                        p[-1] = '\n';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'r':
                        p[-1] = '\r';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 't':
                        p[-1] = '\t';
                        _memmove(p, p + 1, end - p);
                        end--;
                        break;
                    case 'u':
                    {
                        unsigned int x;

                        p++;

                        /* Expecting 4 hex digits: XXXX */
                        if (end - p < 4)
                            RETURN(JSON_EOF);

                        if (_HexStr4ToUint(p, &x) != 0)
                            RETURN(JSON_BAD_SYNTAX);

                        if (x >= 256)
                        {
                            /* ATTN.B: UTF-8 not supported yet! */
                            RETURN(JSON_UNSUPPORTED);
                        }

                        /* Overwrite '\' character */
                        p[-2] = x;

                        /* Remove "uXXXX" */
                        _memmove(p - 1, p + 4, end - p - 3);

                        p = p - 1;
                        end -= 5;
                        break;
                    }
                    default:
                    {
                        RETURN(JSON_FAILED);
                    }
                }
            }
            else
            {
                p++;
            }
        }
    }

#if 0
    Dump(stdout, "GETSTRING", *str, strlen(*str));
#endif

    return JSON_OK;
}

static int _Expect(json_parser_t* self, const char* str, size_t len)
{
    if (self->end - self->ptr >= (ptrdiff_t)len &&
        _memcmp(self->ptr, str, len) == 0)
    {
        self->ptr += len;
        return 0;
    }

    return -1;
}

static json_result_t _GetValue(json_parser_t* self);

static json_result_t _GetArray(json_parser_t* self)
{
    json_result_t r;
    char c;

    /* array = begin-array [ value *( value-separator value ) ] end-array */
    for (;;)
    {
        /* Skip whitespace */
        while (self->ptr != self->end && _isspace(*self->ptr))
            self->ptr++;

        /* Fail if output exhausted */
        if (self->ptr == self->end)
            RETURN(JSON_EOF);

        /* Read the next character */
        c = *self->ptr++;

        if (c == ',')
        {
            continue;
        }
        else if (c == ']')
        {
            break;
        }
        else
        {
            self->ptr--;

            if ((r = _GetValue(self)) != JSON_OK)
            {
                RETURN(r);
            }
        }
    }

    return JSON_OK;
}

static json_result_t _GetObject(json_parser_t* self)
{
    json_result_t r;
    char c;

    if ((r = _invoke_callback(
        self,
        JSON_REASON_BEGIN_OBJECT,
        JSON_TYPE_NULL,
        NULL)) != JSON_OK)
    {
        RETURN(r);
    }

    if (self->depth++ == JSON_MAX_NESTING)
        RETURN(JSON_NESTING_OVERFLOW);

    /* Expect: member = string name-separator value */
    for (;;)
    {
        /* Skip whitespace */
        while (self->ptr != self->end && _isspace(*self->ptr))
            self->ptr++;

        /* Fail if output exhausted */
        if (self->ptr == self->end)
            RETURN(JSON_EOF);

        /* Read the next character */
        c = *self->ptr++;

        if (c == '"')
        {
            json_union_t un;

            /* Get name */
            if ((r = _GetString(self, (char**)&un.string)) != JSON_OK)
                RETURN(r);

            self->path[self->depth - 1] = un.string;

            if ((r = _invoke_callback(
                self,
                JSON_REASON_NAME,
                JSON_TYPE_STRING,
                &un)) != JSON_OK)
            {
                RETURN(r);
            }

            /* Expect: name-separator(':') */
            {
                /* Skip whitespace */
                while (self->ptr != self->end && _isspace(*self->ptr))
                    self->ptr++;

                /* Fail if output exhausted */
                if (self->ptr == self->end)
                    RETURN(JSON_EOF);

                /* Read the next character */
                c = *self->ptr++;

                if (c != ':')
                    RETURN(JSON_BAD_SYNTAX);
            }

            /* Expect: value */
            if ((r = _GetValue(self)) != JSON_OK)
                RETURN(r);
        }
        else if (c == '}')
        {
            break;
        }
    }

    if (self->depth == 0)
        RETURN(JSON_NESTING_UNDERFLOW);

    if ((r = _invoke_callback(
        self,
        JSON_REASON_END_OBJECT,
        JSON_TYPE_NULL,
        NULL)) != JSON_OK)
    {
        RETURN(r);
    }

    self->depth--;

    return JSON_OK;
}

static json_result_t _GetNumber(
    json_parser_t* self,
    json_type_t* type,
    json_union_t* un)
{
    char c;
    int isInteger = 1;
    char* end;
    const char* start = self->ptr;

    /* Skip over any characters that can comprise a number */
    while (self->ptr != self->end && _IsNumberChar(*self->ptr))
    {
        c = *self->ptr;
        self->ptr++;

        if (_IsDecimalOrExponent(c))
            isInteger = 0;
    }

    if (isInteger)
    {
        *type = JSON_TYPE_INTEGER;
        un->integer = _strtol(start, &end, 10);
    }
    else
    {
        *type = JSON_TYPE_REAL;
        un->real = _strtod(start, &end);
    }

    if (!end || end != self->ptr)
        RETURN(JSON_BAD_SYNTAX);

    return JSON_OK;
}

/* value = false / null / true / object / array / number / string */
static json_result_t _GetValue(json_parser_t* self)
{
    char c;
    json_result_t r;

    /* Skip whitespace */
    while (self->ptr != self->end && _isspace(*self->ptr))
        self->ptr++;

    /* Fail if output exhausted */
    if (self->ptr == self->end)
        RETURN(JSON_EOF);

    /* Read the next character */
    c = _tolower(*self->ptr++);

    switch (c)
    {
        case 'f':
        {
            json_union_t un;

            if (_Expect(self, JSON_STRLIT("alse")) != 0)
                RETURN(JSON_BAD_SYNTAX);

            un.boolean = 0;

            if ((r = _invoke_callback(
                self,
                JSON_REASON_VALUE,
                JSON_TYPE_BOOLEAN,
                &un)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case 'n':
        {
            if (_Expect(self, JSON_STRLIT("ull")) != 0)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                self,
                JSON_REASON_VALUE,
                JSON_TYPE_NULL,
                NULL)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case 't':
        {
            json_union_t un;

            if (_Expect(self, JSON_STRLIT("rue")) != 0)
                RETURN(JSON_BAD_SYNTAX);

            un.boolean = 1;

            if ((r = _invoke_callback(
                self,
                JSON_REASON_VALUE,
                JSON_TYPE_BOOLEAN,
                &un)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case '{':
        {
            if ((r = _GetObject(self)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case '[':
        {
            if ((r = _invoke_callback(
                self,
                JSON_REASON_BEGIN_ARRAY,
                JSON_TYPE_NULL,
                NULL)) != JSON_OK)
            {
                RETURN(r);
            }

            if ((r = _GetArray(self)) != JSON_OK)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                self,
                JSON_REASON_END_ARRAY,
                JSON_TYPE_NULL,
                NULL)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        case '"':
        {
            json_union_t un;

            if ((r = _GetString(self, (char**)&un.string)) != JSON_OK)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                self,
                JSON_REASON_VALUE,
                JSON_TYPE_STRING,
                &un)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
        default:
        {
            json_type_t type;
            json_union_t un;

            self->ptr--;

            if ((r = _GetNumber(self, &type, &un)) != JSON_OK)
                RETURN(JSON_BAD_SYNTAX);

            if ((r = _invoke_callback(
                self,
                JSON_REASON_VALUE,
                type,
                &un)) != JSON_OK)
            {
                RETURN(r);
            }

            break;
        }
    }

    return JSON_OK;
}

json_result_t json_parser_init(
    json_parser_t* self,
    char* data,
    size_t size,
    json_parser_callback_t callback,
    void* callback_data,
    json_allocator_t* allocator)
{
    if (!self || !data || !size || !callback)
        return JSON_BAD_PARAMETER;

    if (!allocator || !allocator->ja_malloc || !allocator->ja_free)
        return JSON_BAD_PARAMETER;

    _memset(self, 0, sizeof(json_parser_t));
    self->data = data;
    self->ptr = data;
    self->end = data + size;
    self->callback = callback;
    self->callback_data = callback_data;

    return JSON_OK;
}

json_result_t json_parser_parse(json_parser_t* self)
{
    char c;

    /* Check parameters */
    if (!self)
        return JSON_BAD_PARAMETER;

    /* Expect '{' */
    {
        /* Skip whitespace */
        while (self->ptr != self->end && _isspace(*self->ptr))
            self->ptr++;

        /* Fail if output exhausted */
        if (self->ptr == self->end)
            RETURN(JSON_EOF);

        /* Read the next character */
        c = *self->ptr++;

        /* Expect object-begin */
        if (c != '{')
            return JSON_BAD_SYNTAX;
    }

    return _GetObject(self);
}

static int _strtou64(uint64_t* x, const char* str)
{
    char* end;

    *x = _strtoul(str, &end, 10);

    if (!end || *end != '\0')
        return -1;

    return 0;
}

json_result_t json_match(
    json_parser_t* parser,
    const char* pattern,
    unsigned long* index)
{
    json_result_t result = JSON_UNEXPECTED;
    char buf[256];
    char* ptr = NULL;
    const char* pattern_path[JSON_MAX_NESTING];
    size_t pattern_depth = 0;
    unsigned long n = 0;
    size_t pattern_len;

    if (!parser || !parser->path || !pattern)
        RAISE(JSON_BAD_PARAMETER);

    /* Make a copy of the pattern that can be modified */
    {
        pattern_len = _strlen(pattern);

        if (pattern_len < sizeof(buf))
            ptr = buf;
        else if (!(ptr = parser->allocator->ja_malloc(pattern_len + 1)))
            RAISE(JSON_OUT_OF_MEMORY);

        _strcpy(ptr, pattern);
    }

    /* Split the pattern into tokens */
    if ((pattern_depth = _split(ptr, ".", pattern_path,
        JSON_MAX_NESTING)) == (size_t)-1)
    {
        RAISE(JSON_NESTING_OVERFLOW);
    }

    /* Return false if the path sizes are different */
    if (parser->depth != pattern_depth)
    {
        result = JSON_NO_MATCH;
        goto done;
    }

    /* Compare the elements */
    for (size_t i = 0; i < pattern_depth; i++)
    {
        if (_strcmp(pattern_path[i], "#") == 0)
        {
            if (_strtou64(&n, parser->path[i]) != 0)
                RAISE(JSON_TYPE_MISMATCH);
        }
        else if (_strcmp(pattern_path[i], parser->path[i]) != 0)
        {
            result = JSON_NO_MATCH;
            goto done;
        }
    }

    if (index)
        *index = n;

    result = JSON_OK;

done:

    if (ptr && ptr != buf)
        parser->allocator->ja_free(ptr);

    return result;
}

const char* json_result_string(json_result_t result)
{
    switch (result)
    {
        case JSON_OK:
            return "JSON_OK";
        case JSON_FAILED:
            return "JSON_FAILED";
        case JSON_UNEXPECTED:
            return "JSON_UNEXPECTED";
        case JSON_BAD_PARAMETER:
            return "JSON_BAD_PARAMETER";
        case JSON_OUT_OF_MEMORY:
            return "JSON_OUT_OF_MEMORY";
        case JSON_EOF:
            return "JSON_EOF";
        case JSON_UNSUPPORTED:
            return "JSON_UNSUPPORTED";
        case JSON_BAD_SYNTAX:
            return "JSON_BAD_SYNTAX";
        case JSON_TYPE_MISMATCH:
            return "JSON_TYPE_MISMATCH";
        case JSON_NESTING_OVERFLOW:
            return "JSON_NESTING_OVERFLOW";
        case JSON_NESTING_UNDERFLOW:
            return "JSON_NESTING_UNDERFLOW";
        case JSON_BUFFER_OVERFLOW:
            return "JSON_BUFFER_OVERFLOW";
        case JSON_UNKNOWN_VALUE:
            return "JSON_UNKNOWN_VALUE";
        case JSON_OUT_OF_BOUNDS:
            return "JSON_OUT_OF_BOUNDS";
        case JSON_NO_MATCH:
            return "JSON_NO_MATCH";
    }

    /* Unreachable */
    return "UNKNOWN";
}
