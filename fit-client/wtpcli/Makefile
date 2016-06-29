CC=$(TARGET_CC)
LD=$(TARGET_LD)

CC=@set -e;echo "  CC     $<";gcc
LD=@set -e;echo "  LD     $@";gcc

PWD:=$(shell pwd)
RELEASE_DIR=$(PWD)/../../release
DIR_INS:=$(RELEASE_DIR)/usr/local/bin
DIR_ENV:=/usr/local/bin

EXE:=cli
SRC:=$(sort $(wildcard *.c utils/*.c) )
OBJ:=$(patsubst %.c,%.o,$(SRC))

CFLAGS+=-I. -I./utils -include os.h -include utils/utils.h \
		-include types_pub.h -include debug_pub.h $(TARGET_CPPFLAGS)   -g  -std=c99
EXTLIB+=-lcrypt -lutil -lrt
LDFLAGS+= $(TARGET_LDFLAGS)  -lc -lm -ldl -lmbedtls -lcurl  -L/mnt/Chaos-Calmer-15.05/openwrt/build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/json-c-0.12/ipkg-install/usr/lib -ljson-c 

all default : $(EXE)
install: $(DIR_INS)/$(EXE)
env: $(DIR_ENV)/$(EXE)

$(SRC): os.h
$(OBJ): %.o : %.c #$(wildcard *.h utils/*.h tmpl/*.h)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -c -o $@

$(EXE): $(OBJ)
	$(GCC)   -o $@ $^ $(EXTLIB) $(LDFLAGS)

os.h: os.sh
	@set -e; echo "  GEN    $@"; sh $< > $@ || rm $@

clean :
	@set -e; echo "  CLR    $(EXE)"; rm -f $(OBJ) $(EXE)
distclean : clean
	@set -e; echo "  DEL    os.h" ; rm -f os.h 
$(sort $(DIR_ENV)/$(EXE) $(DIR_INS)/$(EXE)) : % : $(EXE)
	@set -e; echo "  INST   $@"; install -m 4777 -s $< $@

.PHONY: all clean distclean install

