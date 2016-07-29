

#########################################
#
#target : all,lib env,install
#
##########################################
CXX = gcc
CXXFLAGS += -Wall -g -I../libs
CXXLDFLAGS= -lpthread
LIBSRC = wake_utils.c linux-utils.c
src = $(wildcard *.c)
obj = $(src:.c=.o)
src += $(LIBSRC)
vpath %.c ../libs
vpath %.h ../libs

progam = program

all: t $(progam)

t:
	@echo $(src)
	@echo $(obj)

$(src:.c=.o): %.o : %.c
	$(CXX) $(CXXFLAGS) $^ -c -o $@ 

$(progam): $(obj)
	$(CXX) $(CXXLDFLAGS) $^ -o $@

clean:
	@rm $(progam) *.o -f
