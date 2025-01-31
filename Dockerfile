FROM alpine:latest AS xmake

RUN apk add --no-cache bash curl git gcc g++ clang make readline-dev ncurses-dev libc-dev linux-headers p7zip unzip libcurl cmake
RUN mkdir /xmake
WORKDIR /xmake
RUN curl -fsSL https://xmake.io/shget.text | bash

FROM xmake AS build
ADD . /nuggit
WORKDIR /nuggit
ENV XMAKE_ROOT=y
ENV PATH="/root/.local/bin:$PATH"

RUN xmake config -m release -y
RUN xmake
RUN cat /nuggit/config.ini | sed 's/\r//g' > /nuggit/build/config.ini

FROM alpine:latest
RUN apk add --no-cache libc-dev linux-headers gcc g++ make curl libcurl
COPY --from=build /nuggit/build/nuggit /usr/bin/nuggit
COPY --from=build /nuggit/build/config.ini ~/.nuggit/config.ini

WORKDIR /

CMD ["nuggit", "--config=~/.nuggit/config.ini"]

EXPOSE 6688/tcp
