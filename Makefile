CC = clang
CFLAGS = -framework JavaScriptCore -framework Security -lcurl -Wall -Wextra
TARGET = krandog

all: $(TARGET)

$(TARGET): runtime.c
	$(CC) $(CFLAGS) -o $(TARGET) runtime.c

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./run-tests.sh

.PHONY: all clean test
