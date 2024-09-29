
.PHONY: all clean

all: usbcap candet neteco
CFLAGS += -g -Wall
LDFLAGS += -g -pthread

usbcap: usbcapture.o
	$(LINK.o) $^ -o $@

candet: link_detect.o link_watch.o sock_operation.o
	$(LINK.o) $^ $(LIBS) -o $@

neteco: net_echo.o sock_operation.o
	$(LINK.o) $^ -o $@

clean:
	rm -f *.o usbcap candet neteco

-include header-dep.mak
