TARGET = jsonsample
CFLAGS = -Wall -Werror
INCLUDES = -I../include
LDFLAGS = -L.. -ljsonprint -ljson

$(TARGET): main.c ../libjson.a
	gcc $(CFLAGS) $(INCLUDES) -c main.c
	gcc $(CFLAGS) $(INCLUDES) -c strings.c
	gcc $(CFLAGS) $(INCLUDES) -o $(TARGET) main.o strings.o $(LDFLAGS)

clean:
	rm -f $(TARGET) main.o strings.o

tests: $(TARGET)
	jsonsample sample.json
	@ echo "=== passed jsonsample test"
