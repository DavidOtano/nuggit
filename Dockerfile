FROM alpine:latest AS alpine-curl
RUN apk update
RUN apk upgrade
RUN apk add --no-cache curl bash git gcc g++ make readline-dev ncurses-dev libc-dev linux-headers p7zip unzip cmake perl-dev nghttp2 nghttp2-dev openssl openssl-dev libpsl-dev wget
WORKDIR /setup
RUN wget https://curl.se/download/curl-8.11.1.tar.gz
RUN tar -xzvf curl-8.11.1.tar.gz
WORKDIR /setup/curl-8.11.1
RUN ./configure --prefix=/usr --with-ssl --with-nghttp2
RUN make -j4
RUN make install
WORKDIR /
RUN rm -rf /setup

FROM alpine-curl AS xmake-build
RUN mkdir /xmake
WORKDIR /xmake
RUN curl -fsSL https://xmake.io/shget.text | bash
RUN rm -rf /xmake

FROM xmake-build AS build-nuggit
ENV PATH="/root/.local/bin:$PATH"
ENV XMAKE_ROOT=y
WORKDIR /
RUN mkdir /nuggit
ADD . /nuggit
WORKDIR /nuggit
RUN rm -rf .xmake
RUN xmake config -m release -y
RUN xmake -j4
RUN mkdir /var/nuggit
RUN cat /nuggit/config.ini | sed 's/\r//g' > /var/nuggit/config.ini
RUN cp /nuggit/build/nuggit /usr/bin/nuggit
WORKDIR /
RUN rm -rf /nuggit

FROM alpine:latest AS nuggit
ENV NG_CONFIG_PATH=/var/nuggit
COPY --from=build-nuggit /var/nuggit /var/nuggit
COPY --from=build-nuggit /lib /lib
COPY --from=build-nuggit /usr/lib /usr/lib
COPY --from=build-nuggit /etc/ssl /etc/ssl
COPY --from=build-nuggit /etc/ssl1.1 /etc/ssl1.1
COPY --from=build-nuggit /usr/bin/curl /usr/bin/curl
COPY --from=build-nuggit /usr/bin/nuggit /usr/bin/nuggit
CMD ["nuggit"]
EXPOSE 6688/tcp
