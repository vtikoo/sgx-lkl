include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

all:

tests: dirs test1 test2 test3

test1:
	./test-verity.sh
	./test-verity.sh 2
	./test-verity.sh 4
	./test-verity.sh 7
	./test-verity.sh 13
	./test-verity.sh 112
	./test-verity.sh 4096
	./test-verity.sh 10000
	./test-verity.sh 20000
	./test-verity.sh 30000

test2: dirs
	dd if=/dev/urandom of=verity bs=4096 count=1000
	veritysetup format verity verity.hash
	$(MAKE) __test2

__test2:
	$(eval TEMPFILE := $(shell /bin/tempfile))
	$(eval NAME := $(shell basename $(TEMPFILE)))
	$(eval ROOTHASH := $(shell vicsetup verityDump verity.hash | grep "^Root hash:" | sed 's/Root hash:[\t ]*//g'))
	vicsetup veritysetupOpen verity $(NAME) verity.hash $(ROOTHASH)
	@ echo "Created /dev/mapper/$(NAME)"
	dd if=/dev/mapper/${NAME} of=tmpfile
	cmp tmpfile verity
	vicsetup verityClose $(NAME)
	rm -rf $(TEMPFILE)

test3: dirs
	dd if=/dev/urandom of=verity bs=4096 count=1000
	veritysetup format verity verity.hash
	$(MAKE) __test3

__test3:
	@ cp verity file
	@ cat verity.hash >> file
	$(eval TEMPFILE := $(shell /bin/tempfile))
	$(eval NAME := $(shell basename $(TEMPFILE)))
	$(eval DATA_SIZE := $(shell stat --printf=%s verity))
	$(eval HASH_AREA_OFFSET := $(DATA_SIZE))
	$(eval ROOTHASH := $(shell vicsetup verityDump verity.hash | grep "^Root hash:" | sed 's/Root hash:[\t ]*//g'))
	vicsetup veritysetupOpen --data-size $(DATA_SIZE) --hash-area-offset $(HASH_AREA_OFFSET) file $(NAME) file $(ROOTHASH)
	@ echo "Created /dev/mapper/$(NAME)"
	dd if=/dev/mapper/${NAME} of=tmpfile
	cmp tmpfile verity
	vicsetup verityClose $(NAME)
	rm -rf $(TEMPFILE)

CLEAN += hashtree verity verity.hash file

DIRS += $(TOP)/vicsetup

include ../../rules.mak
