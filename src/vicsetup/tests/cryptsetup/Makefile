include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

tests: format dump

FORMAT_OPTS += --keyfile KEY
FORMAT_OPTS += --cipher "aes"
FORMAT_OPTS += --cipher-mode "xts-plain64"
FORMAT_OPTS += --luks2
FORMAT_OPTS += --pbkdf argon2i
FORMAT_OPTS += --pbkdf-memory 4096
FORMAT_OPTS += --iter-time 5
FORMAT_OPTS += --pbkdf-parallel 4

format:
	head -c 64 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	vicsetup cryptsetupLuksFormat $(FORMAT_OPTS) LUKS pass

dump:
	vicsetup luksDump LUKS

CLEAN += KEY LUKS

DIRS += $(TOP)/vicsetup

include ../../rules.mak
