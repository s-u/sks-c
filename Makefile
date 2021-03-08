sks: server.c http.c tls.c token.c main.c ulog.c
	$(CC) -I/usr/local/include -DFORKED=1 -DRSERV_DEBUG=1 -DNO_CONFIG_H -DHAVE_TLS=1 -Wall -pedantic -o $@ $^ -lssl -lcrypto 

clean:
	rm -f *.o sks
