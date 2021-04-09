LIBS = -lssl -lcrypto

init: clean client

client:
	gcc client.c -o client $(LIBS)


.PHONY: clean
clean:
	rm -rf client client.o
