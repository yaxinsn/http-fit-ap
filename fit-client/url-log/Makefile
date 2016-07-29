

#########################################
#
#target : all,lib env,install
#
##########################################
CXX = gcc
CXXFLAGS += -Wall -g
CXXLDFLAGS= -lpthread

src = $(wildcard *.c)
obj = $(src:.c=.o)
progam = program

all: t $(progam)

t:
	@echo $(src)
	@echo $(obj)


%.o : %.c
	$(CXX) $(CXXFLAGS) -c -o $@ $(CXXFLAGS) $<

$(progam): $(obj)
	$(CXX) $(CXXLDFLAGS) $^ -o $@

clean:
	@rm $(progam) *.o -f
