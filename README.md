# aws-vpn-client-docker

Run an AWS Client VPN SAML connection in Docker.

## Usage

1. Download your AWS VPN client profile (`cvpn-endpoint-*.ovpn`).
2. Start the container with Docker Compose:

   ```sh
   docker compose up -d
   ```

3. Open <http://localhost:35001> and upload the profile to start the SAML login.

The included HTTP proxy listens on port `8888`. To use it from other LAN
devices or change its port, copy `.env.example` to `.env` and edit the values.

### Docker run

```sh
docker run --name vpn -d \
  --net host \
  --device /dev/net/tun:/dev/net/tun \
  --cap-add NET_ADMIN \
  -e SAVE_PROFILE=true \
  -e AUTO_RECONNECT=true \
  ghcr.io/dangh/aws-vpn-client:latest
```

`SAVE_PROFILE` enables one-click reconnect. Mount a volume at `/data` only if
the saved profile must survive container removal and recreation.

### Remote Docker host

AWS VPN redirects SAML authentication to <http://localhost:35001>. When Docker
runs on a remote host, forward that port to your local machine before opening
the web UI:

```sh
ssh -N \
  -L 35001:localhost:35001 \
  user@remote-host
```

Keep the SSH session open, then visit <http://localhost:35001>. This is local
SSH forwarding (`-L`): the browser's local callback is carried to the remote
container.

## Credits

This image packages the OpenVPN work from
[samm-git/aws-vpn-client](https://github.com/samm-git/aws-vpn-client) and
[botify-labs/aws-vpn-client](https://github.com/botify-labs/aws-vpn-client).
