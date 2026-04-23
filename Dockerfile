FROM alpine:3.20.3 AS ovpn-builder

ARG OPENVPN_VERSION="2.6.12"

WORKDIR /opt/openvpn

RUN apk add --no-cache curl tar libcap-ng-dev linux-headers linux-pam-dev lz4-dev lzo-dev \
        openssl-dev iproute2-minimal build-base pkgconfig libnl3-dev patch

RUN curl --fail -L -o openvpn.tar.gz "https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN_VERSION/openvpn-$OPENVPN_VERSION.tar.gz" \
    && tar xzf openvpn.tar.gz \
    && cd "openvpn-$OPENVPN_VERSION" \
    && curl --fail -o openvpn-aws.patch "https://raw.githubusercontent.com/dangh/aws-vpn-client/refs/heads/master/openvpn-v$OPENVPN_VERSION-aws.patch" \
    && patch -p1 < "openvpn-aws.patch" \
    && ./configure --prefix=/usr --sysconfdir=/etc --sbindir=/usr/sbin --libdir=/usr/lib --with-crypto-library=openssl \
    && make -j"$(getconf _NPROCESSORS_ONLN)" \
    && make DESTDIR=/opt/openvpn/install-root install

FROM --platform=$BUILDPLATFORM golang:1.23.1-alpine3.20 AS server-builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /opt/go-server

COPY server.go ./

# Build go server
RUN go mod init server \
    && CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" go build -o server ./server.go

FROM alpine:3.20.3 AS container

WORKDIR /opt/openvpn

RUN apk add --no-cache bash busybox-binsh openvpn libnl3 openssl bind-tools

COPY --from=ovpn-builder /opt/openvpn/install-root/ /
COPY --from=server-builder /opt/go-server/server /usr/sbin/saml_server
COPY entrypoint.sh .

ENTRYPOINT ["./entrypoint.sh"]
