# aws-vpn-client-docker

Run an AWS Client VPN SAML connection in Docker, using the OpenVPN work from
[samm-git/aws-vpn-client](https://github.com/samm-git/aws-vpn-client) and
[botify-labs/aws-vpn-client](https://github.com/botify-labs/aws-vpn-client).

## Usage

1. Download your AWS VPN client profile (`cvpn-endpoint-*.ovpn`).
2. Start the container:

   ```sh
   docker run --name vpn -d \
     --net host \
     --device /dev/net/tun:/dev/net/tun \
     --cap-add NET_ADMIN \
     -e SAVE_PROFILE=true \
     -e AUTO_RECONNECT=true \
     ghcr.io/dangh/aws-vpn-client:latest
   ```

3. Open <http://localhost:35001>.
4. Upload the `.ovpn` profile to start the SAML login.

For a fork, use `ghcr.io/<owner>/aws-vpn-client:<tag>`.

### Docker Compose

Build and start the VPN and included HTTP proxy:

```sh
docker compose up --build
```

Then open <http://localhost:35001> and upload your profile. The proxy listens on
port `8888`.

Before exposing the proxy to other LAN devices, set `LAN_SUBNET` in
`compose.yml` to their subnet, for example `192.168.10.0/24`. Use a
space-separated value for multiple subnets. The included route hook keeps those
devices able to reach the proxy after the VPN changes the default route.

## Reconnect options

| Setting | Purpose |
| --- | --- |
| `SAVE_PROFILE=true` | Saves a profile after its first successful connection and enables **Reconnect with saved profile**. |
| `AUTO_RECONNECT=true` | Automatically starts SAML authentication when the web UI is visited after a connected session drops. |
| Volume mounted at `/data` | Keeps the saved profile when the container is recreated. |

Auto-reconnect does not run after a fresh container start, a restart, or a failed
initial connection. In those cases, connect manually from the web UI.

## Custom OpenVPN hooks

Mount executable scripts at any of these optional paths:

| Path | Runs when |
| --- | --- |
| `/etc/openvpn/up.sh` | The tunnel is up, after DNS setup |
| `/etc/openvpn/down.sh` | The tunnel is going down |
| `/etc/openvpn/route-up.sh` | Routes are installed |
| `/etc/openvpn/route-pre-down.sh` | Before routes are removed |

Scripts receive the usual OpenVPN environment variables. They must be executable
(`0555` or `+x`). With Compose, a script can be defined inline:

```yaml
services:
  vpn:
    configs:
      - source: route_up
        target: /etc/openvpn/route-up.sh
        mode: 0555

configs:
  route_up:
    content: |
      #!/bin/sh
      echo "route-up ran, gateway is $$route_net_gateway"
```

Escape `$` as `$$` inside Compose `content` blocks to prevent interpolation.

## Supported platforms

Published images support `linux/amd64` and `linux/arm64`.
