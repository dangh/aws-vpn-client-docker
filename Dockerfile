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
ARG OPTIMIZE=false

WORKDIR /opt/go-server

COPY server.go ./

RUN go mod init server \
    && if [ "$OPTIMIZE" = "true" ]; then \
         apk add --no-cache upx \
         && CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" go build -ldflags="-s -w" -o server ./server.go \
         && upx --best server; \
       else \
         CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" go build -o server ./server.go; \
       fi

FROM alpine:3.20.3 AS container

WORKDIR /opt/openvpn

RUN apk add --no-cache openvpn libnl3 openssl bind-tools

COPY --from=ovpn-builder /opt/openvpn/install-root/ /
COPY --from=server-builder /opt/go-server/server /usr/sbin/awsvpn
COPY etc/openvpn/ /etc/openvpn/
RUN chmod +x /etc/openvpn/route-up.sh /etc/openvpn/route-pre-down.sh

ENTRYPOINT ["/usr/sbin/awsvpn"]
