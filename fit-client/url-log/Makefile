

#########################################
#
#target : all,lib env,install
#
##########################################
#CXX = gcc
CC=$(TARGET_CC)
LD=$(TARGET_LD)
CXXFLAGS += -Wall -g -I../libs 
CXXFLAGS += $(TARGET_CPPFLAGS) -I$(BUILD_DIR)/linux-ramips_mt7620/iptables-1.4.21/include
$(warning "CXX $(CXX)"   CC $(CC));
CXXLDFLAGS = $(TARGET_LDFLAGS) -lpthread -L./ -lnetfilter_log -lnetfilter_log_libipulog 
LIBSRC = wake_utils.c linux-utils.c
src = $(wildcard *.c)
obj = $(src:.c=.o)
src += $(LIBSRC)
vpath %.c ../libs
vpath %.h ../libs

progam = url_log

all: t $(progam)

t:
	@echo $(src)
	@echo $(obj)

$(src:.c=.o): %.o : %.c
	$(CC) $(CXXFLAGS) $^ -c -o $@ 

$(progam): $(obj)
	$(CC) $(CXXLDFLAGS)  -o $@ $^

clean:
	@rm $(progam) *.o -f
