CC	:= $(CROSS_COMPILE)gcc
CFLAGS	:= -Wall -Wextra -std=c11 -Os -DNDEBUG
LDFLAGS	:= -lcrypt -lm

SRC	:= webapi.c monocypher.c cJSON.c b64_decode.c b64_encode.c b64_buffer.c
OBJ	:= $(SRC:.c=.o)

TARGET	:= webapi

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

install:
	install -D -m 0755 $(TARGET) $(DESTDIR)/var/www/cgi-bin/$(TARGET)
