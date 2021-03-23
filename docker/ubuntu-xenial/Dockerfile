FROM ubuntu:xenial

ENV LANG C
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates sudo git build-essential automake autoconf clang wget libpcap-dev libnet1-dev libjson-c-dev iproute2 && \
    apt-get clean

RUN useradd -ms /bin/bash ssldump
RUN passwd -d ssldump
RUN printf 'Defaults:ssldump env_keep=LD_LIBRARY_PATH\n' | tee -a /etc/sudoers
RUN printf 'ssldump ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER ssldump

RUN mkdir /home/ssldump/openssl && \
	cd /home/ssldump/openssl && \
	wget https://www.openssl.org/source/openssl-1.1.1j.tar.gz && \
	tar xvfz openssl-1.1.1j.tar.gz && \
	cd openssl-1.1.1j && \
	./config && \
	make -j 2

RUN cd /home/ssldump && \
	git clone https://github.com/adulau/ssldump.git build

RUN cd /home/ssldump/build && \
	./autogen.sh && \
	./configure CFLAGS="-I../openssl/openssl-1.1.1j/include" LDFLAGS="-L../openssl/openssl-1.1.1j -lcrypto -lssl" && \
	make && \
	sudo make install

ENV LD_LIBRARY_PATH /home/ssldump/openssl/openssl-1.1.1j
RUN printf '#!/bin/bash\nexport LD_LIBRARY_PATH=/home/ssldump/openssl/openssl-1.1.1j\nssldump $@\n' > /home/ssldump/run_ssldump.sh
RUN chmod +x /home/ssldump/run_ssldump.sh

WORKDIR "/home/ssldump"

CMD ["/bin/bash"]
