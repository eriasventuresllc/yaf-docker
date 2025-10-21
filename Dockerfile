FROM ubuntu:20.04

LABEL repo="github.com/jasimpson/Dockerfiles"
LABEL authors="@jasimpson,@lapolonio"

ENV LIBFIXBUF_VERSION=2.3.0
ENV YAF_VERSION=2.15.0
ENV SM_VERSION=1.10.0
ENV SILK_VERSION=3.22.1
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install Dependencies
RUN apt-get update && apt-get install -y \
        build-essential \
        gcc \
        libglib2.0-dev \
        libpcap-dev \
        libpcre3-dev \
        python3-dev \
        iputils-ping \
        python3 \
        libssl-dev \
        dos2unix \
        pkg-config \
        tzdata
RUN ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && dpkg-reconfigure -f noninteractive tzdata

#RUN apt-get clean && \
#    rm -rf /var/cache/apt/* && \
#    rm -rf /var/lib/apt/lists/*

# Build libfixbuf
ADD https://tools.netsa.cert.org/releases/libfixbuf-$LIBFIXBUF_VERSION.tar.gz /tmp/libfixbuf-$LIBFIXBUF_VERSION.tar.gz
WORKDIR "/tmp"
RUN tar -zxvf libfixbuf-$LIBFIXBUF_VERSION.tar.gz
WORKDIR "/tmp/libfixbuf-$LIBFIXBUF_VERSION"
RUN ./configure && make && make install

# Build yaf
ADD https://tools.netsa.cert.org/releases/yaf-$YAF_VERSION.tar.gz /tmp/yaf-$YAF_VERSION.tar.gz
WORKDIR "/tmp"
RUN tar -zxvf yaf-$YAF_VERSION.tar.gz
WORKDIR "/tmp/yaf-$YAF_VERSION"
RUN ./configure --enable-applabel --enable-plugins --enable-entropy --with-openssl && make && make install

# Build super_mediator
ADD https://tools.netsa.cert.org/releases/super_mediator-$SM_VERSION.tar.gz /tmp/super_mediator-$SM_VERSION.tar.gz
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
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN apt-get update
VOLUME ["/files"]

COPY run.sh /run.sh
RUN mkdir -p /opt/yaf
COPY files/convert.py /opt/yaf/convert.py
COPY files/dpi_multi_file_extra_fields.conf /opt/yaf/dpi_multi_file_extra_fields.conf
RUN chmod 0755 /run.sh
RUN chmod 0755 /opt/yaf/convert.py
RUN dos2unix /run.sh
ENTRYPOINT ["/run.sh"]