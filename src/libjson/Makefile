TARGET = libjson.a

CFLAGS += -g
CFLAGS += -O3
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wextra
CFLAGS += -Wno-type-limits

INCLUDES += -Iinclude

SOURCES += $(wildcard *.c)

HEADERS += include/json.h

OBJECTS = $(SOURCES:.c=.o)

$(TARGET): $(OBJECTS)
	ar rv $(TARGET) $(OBJECTS)

%.o: %.c $(HEADERS)
	gcc -c $(CFLAGS) $(DEFINES) $(INCLUDES) -o $@ $<

clean:
	rm -rf $(OBJECTS) $(TARGET)
	$(MAKE) -C jsonprint clean
	$(MAKE) -C sample clean

tests:
	@ $(MAKE) -s -C sample tests
	@ $(MAKE) -s -C jsonprint tests
