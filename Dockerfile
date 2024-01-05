FROM ubuntu:16.04

LABEL repo="github.com/jasimpson/Dockerfiles"
LABEL authors="@jasimpson,@lapolonio"

ENV LIBFIXBUF_VERSION=2.3.0
ENV YAF_VERSION=2.14.0
ENV SM_VERSION=1.9.1
ENV SILK_VERSION=3.22.1

# Install Dependencies
RUN apt-get upgrade
RUN apt-get update
RUN apt-get install -y \
        build-essential \
        gcc \
        libglib2.0-dev \
        libpcap-dev \
        python-dev \
        iputils-ping \
        python3 \
        dos2unix

#RUN apt-get clean && \
#    rm -rf /var/cache/apt/* && \
#    rm -rf /var/lib/apt/lists/*

# Build libfixbuf
ADD http://tools.netsa.cert.org/releases/libfixbuf-$LIBFIXBUF_VERSION.tar.gz /tmp/libfixbuf-$LIBFIXBUF_VERSION.tar.gz
WORKDIR "/tmp"
RUN tar -zxvf libfixbuf-$LIBFIXBUF_VERSION.tar.gz
WORKDIR "/tmp/libfixbuf-$LIBFIXBUF_VERSION"
RUN ./configure && make && make install

# Build yaf
ADD http://tools.netsa.cert.org/releases/yaf-$YAF_VERSION.tar.gz /tmp/yaf-$YAF_VERSION.tar.gz
WORKDIR "/tmp"
RUN tar -zxvf yaf-$YAF_VERSION.tar.gz
WORKDIR "/tmp/yaf-$YAF_VERSION"
RUN ./configure --enable-applabel --enable-plugins --enable-entropy && make && make install

# Build super_mediator
ADD http://tools.netsa.cert.org/releases/super_mediator-$SM_VERSION.tar.gz /tmp/super_mediator-$SM_VERSION.tar.gz
WORKDIR "/tmp"
RUN tar -zxvf super_mediator-$SM_VERSION.tar.gz
WORKDIR "/tmp/super_mediator-$SM_VERSION"
RUN ./configure --with-mysql=no && make && make install

# Build silk
ADD https://tools.netsa.cert.org/releases/silk-$SILK_VERSION.tar.gz /tmp/silk-$SILK_VERSION.tar.gz
WORKDIR "/tmp"
RUN tar -zxvf silk-$SILK_VERSION.tar.gz
WORKDIR "/tmp/silk-$SILK_VERSION"
RUN ./configure \
    --with-libfixbuf=/usr/local/lib/pkgconfig/ \
    --with-python \
    --enable-ipv6 && \
    make && make install

RUN ldconfig
RUN apt-get update
RUN apt-get install -y dos2unix
VOLUME ["/files"]

COPY run.sh /run.sh
COPY files/convert.py /files/convert.py
RUN chmod 0755 /run.sh
RUN chmod 0755 /files/convert.py
RUN dos2unix /run.sh
ENTRYPOINT ["/run.sh"]