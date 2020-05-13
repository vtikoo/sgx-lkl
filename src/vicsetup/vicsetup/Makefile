include ../defs.mak

PROGRAM = vicsetup

INCLUDES += -I$(TOP)/libvicsetup/include

SOURCES += main.c

LDFLAGS += -L$(TOP)/libvicsetup -lvicsetup
LDFLAGS += -L$(LIBJSON_DIR) -ljson
LDFLAGS += -ldevmapper
LDFLAGS += -lmbedcrypto
LDFLAGS += -lpthread

DIRS += $(LIBJSON_DIR)
DIRS += $(TOP)/libvicsetup

include ../rules.mak
-include depend.mak

OPTS += --keyfile KEY
OPTS += --cipher "aes"
OPTS += --cipher-mode "xts-plain64"
OPTS += --luks2

xxx:
	head -c 64 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	vicsetup cryptsetupLuksFormat $(OPTS) LUKS pass
