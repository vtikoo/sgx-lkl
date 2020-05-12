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

xxx:
	head -c 32MB /dev/zero > LUKS
	vicsetup luksFormat --luks2 LUKS pass
	vicsetup luksDump LUKS
