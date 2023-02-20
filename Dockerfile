ARG DIST=kinetic
FROM ubuntu:${DIST}
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
    && apt-get install -y \
    make \
    openssl \
    python3 \
    python3-click \
    python3-pyasn1 \
    python3-pyasn1-modules \
    ruby-full \
    xml2rfc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN gem install kramdown-rfc2629
RUN mkdir -m 777 /var/cache/xml2rfc