all:
	gcc  -Wall -Wextra -Werror ipk-sniffer.c -lpcap  -o  ipk-sniffer 

clean:
	rm -f ipk-sniffer
