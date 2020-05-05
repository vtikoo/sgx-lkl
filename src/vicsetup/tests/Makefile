include ../defs.mak

all:

DIRS = luks1 luks2 integrity verity

tests:
	$(MAKE) -C $(TOP)/vicsetup
	$(foreach i, $(DIRS), $(MAKE) -C $(i) tests $(NL) )

clean:
	$(foreach i, $(DIRS), $(MAKE) -C $(i) clean $(NL) )
