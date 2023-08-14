#FROM debian:bookworm-slim
#FROM debian:bullseye-slim
#FROM debian:buster-slim
FROM ubuntu:jammy
#FROM ubuntu:focal


ENV LANG C
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates sudo git build-essential cmake ninja-build clang libssl-dev libpcap-dev libnet1-dev libjson-c-dev iproute2 && \
    apt-get clean

RUN useradd -ms /bin/bash ssldump
RUN passwd -d ssldump
RUN printf 'ssldump ALL=(ALL) ALL\n' | tee -a /etc/sudoers

USER ssldump

RUN cd /home/ssldump && \
    git clone https://github.com/adulau/ssldump.git ssldump-build

RUN cd /home/ssldump/ssldump-build && \
    cmake -G Ninja -B build && \
    ninja -C build && \
    sudo ninja -C build install

WORKDIR "/home/ssldump"

CMD ["/bin/bash"]
