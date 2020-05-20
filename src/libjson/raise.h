#ifndef _JSON_RAISE_H
#define _JSON_RAISE_H

#define RAISE(RAISE)                                            \
    do                                                          \
    {                                                           \
        result = RAISE;                                         \
        goto done;                                              \
    }                                                           \
    while (0)

#define CHECK(RESULT)                                            \
    do                                                           \
    {                                                            \
        json_result_t _r_ = RESULT;                              \
        if (_r_ != JSON_OK)                                      \
        {                                                        \
            result = _r_;                                        \
            goto done;                                           \
        }                                                        \
    }                                                            \
    while (0)

#endif /* _JSON_RAISE_H */
