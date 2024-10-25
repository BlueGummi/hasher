CC = clang++
CFLAGS = -std=c++20
LDFLAGS = -lcrypto

TARGET = main
SRC = main.cpp
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET)
