CC = gcc
CFLAGS = -O2
OBJFILES = main.o rsa.o utils.o

TARGET = assign_3


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) -lm

clean:
	rm -f $(TARGET) *.o *.key
