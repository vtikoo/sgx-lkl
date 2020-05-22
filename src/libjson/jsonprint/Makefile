TARGET = jsonprint
CFLAGS = -Wall
INCLUDES = -I../include
LDFLAGS = -L.. -ljsonprint -ljson

$(TARGET): main.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) main.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

tests: $(TARGET) test1 test2

test1:
	$(eval TMP := $(shell /bin/mktemp))
	jsonprint sample.json > $(TMP)
	diff ${TMP} expected.sample.json
	@ echo "=== passed jsonprint test1"

test2:
	$(eval TMP := $(shell /bin/mktemp))
	jsonprint array.json > $(TMP)
	diff ${TMP} expected.array.json
	@ echo "=== passed jsonprint test2"
