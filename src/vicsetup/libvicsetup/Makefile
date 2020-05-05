include ../defs.mak

ARCHIVE = libvicsetup.a

CFLAGS += -Wno-type-limits

INCLUDES += -I/usr/local/include
INCLUDES += -Iargon2/include
INCLUDES += -Iinclude
INCLUDES += -I$(LIBJSON_DIR)/include

SOURCES += $(wildcard *.c)
SOURCES += argon2/src/argon2.c
SOURCES += argon2/src/core.c
SOURCES += argon2/src/blake2/blake2b.c
SOURCES += argon2/src/thread.c
SOURCES += argon2/src/encoding.c
SOURCES += argon2/src/opt.c

include ../rules.mak

-include depend.mak
