CFLAGS += -g
CFLAGS += -O3
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wextra
CFLAGS += -Wno-type-limits

INCLUDES += -Iinclude

SOURCES += $(wildcard *.c)

OBJECTS = $(SOURCES:.c=.o)

HEADERS += include/json.h include/jsonprint.h

all: $(OBJECTS)
	ar rv libjson.a json.o
	ar rv libjsonprint.a jsonprint.o
	$(MAKE) -C jsonprint
	$(MAKE) -C sample

%.o: %.c $(HEADERS)
	gcc -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<


clean:
	rm -rf $(OBJECTS) libjsonprint.a libjson.a
	$(MAKE) -C jsonprint clean
	$(MAKE) -C sample clean

tests:
	@ $(MAKE) -s -C sample tests
	@ $(MAKE) -s -C jsonprint tests
