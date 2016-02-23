TARGET = test_e1

CFLAGS += -I.

SOURCES = ../daemon/protocol.c
INCLUDES = ../daemon/protocol.h

SOURCES += $(wildcard *.c)
INCLUDES += $(wildcard *.h)
OBJECTS=$(SOURCES:%.c=%.o)

CFLAGS+=$(shell pkg-config --cflags glib-2.0 gio-2.0)
LDFLAGS+=$(shell pkg-config --libs glib-2.0 gio-2.0)

all: $(TARGET)

# $(OBJECTS): $(SOURCES)
%.o: %.c ${INCLUDES}
	$(CC) -c -o $@ $(CFLAGS) $<


$(TARGET): $(OBJECTS) 
	$(CC) -o $(TARGET) $(LDFLAGS) $(CXXFLAGS) ${LIBS} $(OBJECTS)

clean:
	$(RM) $(OBJECTS) $(TARGET)

.PHONY: all clean
