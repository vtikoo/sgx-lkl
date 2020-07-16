FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -pthread -g -o rt_sigqueueinfo01 rt_sigqueueinfo01.c

FROM alpine:3.6

COPY --from=builder rt_sigqueueinfo01 .
