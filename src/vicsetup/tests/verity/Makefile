include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

all:

tests: dirs
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

CLEAN += hashtree verity verity.hash

DIRS += $(TOP)/vicsetup

include ../../rules.mak
