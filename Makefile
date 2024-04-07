CC = clang++
CFLAGS = -std=c++20
LDFLAGS = -lcrypto

TARGET = main
SRC = main.cpp
HDR = computehash.h
all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

clean:
	rm -f $(TARGET)
