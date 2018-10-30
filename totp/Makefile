CC = gcc
CCFLAGS = -Wall -O3 -fpic -g3
LIBS = -lgcrypt

SOURCES = $(wildcard *.c)
OTP_OBJ = otp.o
BE_OBJ = base32.o
TEST_SRC = gen_otp.c
TEST_OBJ = gen_otp.o
TEST_EXE = gen_otp

all: $(OTP_OBJ) $(BE_OBJ) $(TEST_OBJ) $(SOURCES)
	$(CC) -o $(TEST_EXE) $(BE_OBJ) $(OTP_OBJ) $(TEST_OBJ) $(LIBS)

%.o: %.c
	$(CC) $(CCFLAGS) -c $< -o $@

.PHONY: clean
clean: 
	rm -f *.o $(TEST_EXE)
