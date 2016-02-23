DIRS = daemon test

.PHONY: all $(DIRS)

default: all

all: $(DIRS)

$(DIRS):
	$(MAKE) -C $@

clean:
	for i in $(DIRS); do $(MAKE) -C $$i $@ ; done
