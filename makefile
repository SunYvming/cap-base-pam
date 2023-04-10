CC = gcc

CFLAGS := -shared -fPIC -g
LFLAGS := -lpam -lcap

SRCS := $(wildcard *.c)
SUBMAKE := $(wildcard */makefile)
OBJS := $(patsubst %.c, %.o, $(wildcard */*.c))
TARGET := pam_ucas_cap
CLEAN_LIST := $(TARGET).so


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(SRCS) $(OBJS) $(CFLAGS) $(LFLAGS) -o $(TARGET).so

$(OBJS):
	@for dir in $(SUBMAKE); do \
		echo "make -C $${dir%/*} all"; \
		make -C $${dir%/*}; \
	done


clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)
	@for dir in $(SUBMAKE); do \
		echo "make -C $${dir%/*} clean"; \
		make -C $${dir%/*} clean; \
	done

install:
	@echo INSTALL $(TARGET)
	@cp $(TARGET).so /lib/security/
	@cp login-cap /etc/pam.d/

uninstall:
	@echo UNINSTALL $(TARGET)
	@rm -f /lib/security/$(TARGET).so
	@rm /etc/pam.d/login-cap
