include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

tests: format format2

##==============================================================================
##
## format:
##
##==============================================================================

FORMAT_OPTS += --keyfile KEY
FORMAT_OPTS += --cipher "aes"
FORMAT_OPTS += --cipher-mode "xts-plain64"
FORMAT_OPTS += --luks2
FORMAT_OPTS += --pbkdf argon2i
FORMAT_OPTS += --iter-time 5
FORMAT_OPTS += --pbkdf-memory 4096
FORMAT_OPTS += --pbkdf-parallel 4

format:
	head -c 64 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	vicsetup cryptsetupLuksFormat $(FORMAT_OPTS) LUKS pass

##==============================================================================
##
## format2:
##
##==============================================================================

FORMAT2_OPTS += --keyfile KEY
FORMAT2_OPTS += --cipher "aes"
FORMAT2_OPTS += --cipher-mode "xts-plain64"
FORMAT2_OPTS += --luks2
FORMAT2_OPTS += --pbkdf pbkdf2
#FORMAT2_OPTS += --hash sha256
FORMAT2_OPTS += --hash sha512
FORMAT2_OPTS += --slot-iterations 4000

format2:
	head -c 64 /dev/urandom > KEY
	head -c 32M /dev/zero > LUKS
	vicsetup cryptsetupLuksFormat $(FORMAT2_OPTS) LUKS pass

##==============================================================================
##
## dump:
##
##==============================================================================

dump:
	vicsetup luksDump LUKS

##==============================================================================
##
## csformat1:
##
##==============================================================================

CSFORMAT1_OPTS += --type luks2
CSFORMAT1_OPTS += --iter-time 8
CSFORMAT1_OPTS += --pbkdf-memory 1024
CSFORMAT1_OPTS += --pbkdf-parallel 2

csformat1:
	head -c 32M /dev/zero > LUKS
	cryptsetup luksFormat $(CSFORMAT1_OPTS) LUKS

##==============================================================================
##
## csformat2:
##
##==============================================================================

CSFORMAT2_OPTS += --type luks2
CSFORMAT2_OPTS += --pbkdf pbkdf2
CSFORMAT2_OPTS += --hash sha512
CSFORMAT2_OPTS += --iter-time 1

csformat2:
	head -c 32M /dev/zero > LUKS
	cryptsetup luksFormat $(CSFORMAT2_OPTS) LUKS

##==============================================================================
##
## standard rules:
##
##==============================================================================

CLEAN += KEY LUKS

DIRS += $(TOP)/vicsetup

include ../../rules.mak
