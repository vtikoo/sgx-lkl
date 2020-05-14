include ../../defs.mak

.PHONY: integrity

export PATH+=:$(TOP)/vicsetup

all:

INTEGRITY_OPTS += --luks2
INTEGRITY_OPTS += --uuid $(UUID)
INTEGRITY_OPTS += --integrity "hmac(sha256)"
INTEGRITY_OPTS += --keyfile keyfile

tests: dirs integrity

UUID=11e8a94c-938d-4869-b623-cc3cd5ce8fed

integrity:
	head -c 64 /dev/urandom > keyfile
	head -c 32M /dev/zero > integrity
	vicsetup luksFormat $(INTEGRITY_OPTS) integrity pass
	vicsetup luksOpen integrity pass integrity
	$(eval TMP1 := $(shell /bin/mktemp))
	dd if=/dev/urandom of=$(TMP1) bs=4096 count=1
	cat $(TMP1) > /dev/mapper/integrity
	vicsetup luksClose integrity
	vicsetup luksOpen integrity pass integrity
	$(eval TMP2 := $(shell /bin/mktemp))
	dd if=/dev/mapper/integrity of=$(TMP2) bs=4096 count=1
	vicsetup luksClose integrity
	cmp $(TMP1) $(TMP2)
	rm -f $(TMP1) $(TMP2)

CLEAN += integrity keyfile

DIRS += $(TOP)/vicsetup

include ../../rules.mak
