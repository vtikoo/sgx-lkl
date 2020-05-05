include ../../defs.mak

export PATH+=:$(TOP)/vicsetup

SIZE=32M

UUID=11e8a94c-938d-4869-b623-cc3cd5ce8fed

all:

tests: dirs luksFormat luksChangeKey luksAddKey luksRemoveKey luksGetMasterKey luksOpen luksClose

keyfile:
	@ head -c 64 /dev/random > keyfile

luksFormat: keyfile
	head -c $(SIZE) /dev/zero > luksfile
	vicsetup luksFormat --uuid $(UUID) --keyfile keyfile luksfile pass1

luksChangeKey:
	vicsetup luksChangeKey luksfile pass1 passx
	vicsetup luksChangeKey luksfile passx pass1

luksAddKey:
	vicsetup luksAddKey luksfile pass1 pass2
	vicsetup luksAddKey luksfile pass2 pass3
	vicsetup luksAddKey luksfile pass3 pass4
	vicsetup luksAddKey luksfile pass4 pass5

luksRemoveKey:
	vicsetup luksRemoveKey luksfile pass2
	vicsetup luksRemoveKey luksfile pass3
	vicsetup luksRemoveKey luksfile pass4

luksGetMasterKey:
	vicsetup luksGetMasterKey luksfile pass1
	vicsetup luksGetMasterKey luksfile pass5
	od -t x1 --address-radix=n keyfile

dump:
	vicsetup luksDump luksfile
	cryptsetup luksDump luksfile

luksOpen:
	vicsetup luksOpen luksfile pass1 luksfile

luksClose:
	vicsetup luksClose luksfile

CLEAN += keyfile
CLEAN += luksfile

DIRS += $(TOP)/vicsetup

include ../../rules.mak
