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

## Two profiles at once

The default `compose.yml` runs **two** profiles simultaneously, each exposed as
its own proxy:

| Profile | Web UI                     | Proxy            |
| ------- | -------------------------- | ---------------- |
| A       | <http://localhost:35010>   | `localhost:8888` |
| B       | <http://localhost:35011>   | `localhost:8889` |

AWS requires the SAML callback to land on the fixed URL
`http://127.0.0.1:35001` for *every* profile, so that host port can belong to
only one process. A small `dispatcher` service owns `35001` and forwards each
SAML login to whichever profile started authenticating last.

Because of that shared port, **authenticate one profile at a time**:

1. Open profile A's UI (<http://localhost:35010>), upload its profile, finish
   the SAML login, wait for **Connected**.
2. Open profile B's UI (<http://localhost:35011>), upload its profile, finish
   the SAML login.

Both tunnels then stay up together — use `localhost:8888` for A and
`localhost:8889` for B. Change the proxy ports in `.env`
(`PROXY_PORT_A` / `PROXY_PORT_B`).

> Re-authenticate a profile only while it is disconnected. Re-auth while its
> tunnel is up can route the dispatcher's reply into the tunnel; add the Docker
> bridge subnet to `LAN_SUBNET` if you hit this.

Need only one profile? Delete the `-b` services (and the dispatcher, publishing
`35001:35001` directly on `vpn-a`).

## Profile mode: every profile in one container

One container runs every profile, each as its own tailnet node (embedded in
[sing-box](https://sing-box.sagernet.org)), managed from a dashboard:

| Where | What |
| ----- | ---- |
| node port 80 | HTTP proxy: the profile's domains (`.x` = every subdomain of x) go through its tunnel, everything else direct |
| node port 8080, `http://localhost:35001` | dashboard (plain HTTP; the tailnet encrypts it) |

The dashboard lists every profile with its status, and can connect (upload a
`.ovpn`, or reconnect with the saved one), disconnect, add a profile (name, tailnet
hostname, domains), edit those, and delete a profile. A new node shows its Tailscale
login link in the dashboard. Changing a hostname or domains, or adding or deleting a
profile, restarts sing-box: proxy connections and tailnet nodes of all profiles drop
for a few seconds; VPN sessions stay up.

- The profiles live in `/data/profiles.json`. On first start `AWSVPN_CONFIG` (optional)
  seeds it:

  ```json
  {
    "tailnet": "example.ts.net",
    "domains": [".amazonaws.com", ".aws"],
    "profiles": [
      { "name": "corp", "hostname": "corp-proxy" },
      { "name": "prod", "hostname": "prod-proxy", "domains": [".amazonaws.com"] }
    ]
  }
  ```

  The top-level `domains` are the default for profiles without their own and for
  profiles added later. After the first start the seed file is not read again.
- Profile mode starts when `AWSVPN_CONFIG` is set or `/data/profiles.json` exists.
- Each profile's data is in `/data/<id>/`: `profile.ovpn` (with `SAVE_PROFILE=true`)
  and `tailscale/` (the node key). Delete moves it to `/data/.trash/`. A deleted
  profile's node stays in the Tailscale admin console (offline) until you remove it.
- The tunnels never take the default route: profile *n* uses device `tun<n>`, and only
  its proxy's VPN traffic (firewall mark and routing table 100+*n*) enters it. While a
  tunnel is down, its VPN domains fail instead of going direct.
- VPN domains resolve through the DNS server the VPN pushed; everything else through
  the container's resolver.
- The proxy never reaches the container's loopback or link-local addresses, and its
  direct path never reaches private networks. The dashboard answers only its own host names (localhost, 127.0.0.1, the nodes) and refuses POSTs without its own Origin.
- Port 35001 takes the SAML callback for whichever profile began auth last: log in one
  profile at a time.

```sh
docker run -d --name awsvpn --init --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.conf.all.rp_filter=2 \
  -p 127.0.0.1:35001:35001 \
  -e AWSVPN_CONFIG=/config.json -e SAVE_PROFILE=true \
  -v ./config.json:/config.json:ro -v awsvpn-data:/data \
  ghcr.io/dangh/aws-vpn-client:master
```

`rp_filter=2` (loose) is required: replies arrive on a tunnel that the main routing
table does not route to.

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

When running two profiles, forward the callback port plus each web UI:

```sh
ssh -N \
  -L 35001:localhost:35001 \
  -L 35010:localhost:35010 \
  -L 35011:localhost:35011 \
  user@remote-host
```

### UI under its own name

When the web UI is reached by another name (for example a Tailscale node that
forwards to the container), set `PUBLIC_URL` to that UI's full URL, e.g.
`http://corp.example.ts.net:35001`. After the SAML login the browser returns
there instead of `http://localhost:$PUBLIC_PORT`. The callback itself still goes
to `http://127.0.0.1:35001` on the browser's machine, so keep the `-L 35001`
forward.

## Credits

This image packages the OpenVPN work from
[samm-git/aws-vpn-client](https://github.com/samm-git/aws-vpn-client) and
[botify-labs/aws-vpn-client](https://github.com/botify-labs/aws-vpn-client).
