TARGET = jsonprint
CFLAGS = -Wall
INCLUDES = -I../include
LDFLAGS = -L.. -ljsonprint -ljson

$(TARGET): main.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) main.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

tests: $(TARGET)
	$(eval TMP := $(shell /bin/mktemp))
	jsonprint sample.json > $(TMP)
	diff ${TMP} expected.json
	@ echo "=== passed jsonprint test"
