include defs.mak

all:
	$(MAKE) -C libvicsetup
	$(MAKE) -C vicsetup

clean:
	$(MAKE) -C libvicsetup clean
	$(MAKE) -C vicsetup clean
	$(MAKE) -C tests clean

tests:
	$(MAKE) -C tests tests

depend:
	$(MAKE) -C libvicsetup depend
	$(MAKE) -C vicsetup depend
