# aws-vpn-client-docker

> [!IMPORTANT]
> This repository is largely simply packaging other authors' work!
> 
> ## Credits
> 
> ### [samm-git/aws-vpn-client](https://github.com/samm-git/aws-vpn-client)
> 
> Alex Samorukov is the mastermind behind this implementation. He figured out how AWS patches the openvpn client and
> created the first implementations. Be sure to read his [blog](https://smallhacks.wordpress.com/2020/07/08/aws-client-vpn-internals/)
> on for more details.
> 
> ### [botify-labs/aws-vpn-client](https://github.com/botify-labs/aws-vpn-client)
> 
> Botify Labs maintains the `.patch` files for more recent versions of OpenVPN than what are available originally
> in Alex's repository.

---

This repository aims to package the work of Alex Samorukov and Botify Labs on making OpenVPN compatible with AWS VPN SAML.

## How to use

### Use a prebuilt container
1. Download your AWS VPN client profile into a directory
2. Run `docker run --name vpn -d --net host -v /path/to/profile.ovpn:/opt/openvpn/profile.ovpn:ro -e SAVE_PROFILE=true -v vpn-data:/data --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN ghcr.io/dangh/aws-vpn-client:latest`
   - `-e SAVE_PROFILE=true -v vpn-data:/data` persists an uploaded profile for the web UI's Reconnect button (optional; see below).
   1. Run `docker logs -f vpn` to grab the login link
   2. After logging in, you can safely exit the log tail with `Ctrl-C`
3. Enjoy

If you are using a fork, the image path will be `ghcr.io/<owner>/aws-vpn-client:<tag>`.

### Build the container yourself
1. Clone this repository
2. Download your AWS VPN client profile into a directory.
3. Adjust the mount source (`./profile.ovpn`) in `compose.yml` to read your ovpn profile file (`cvpn-endpoint-*.ovpn`)
   1. Don't change the mount target (`/opt/openvpn/profile.ovpn`)!
4. Run `docker compose up --build`
   1. Also grab the login link from `docker compose logs`
6. Enjoy

## Save a profile for one-click reconnect

Set the `SAVE_PROFILE` env var (`1`/`true`/`yes`/`on`) to persist an uploaded
`.ovpn` profile to `/data/profile.ovpn` inside the container. The profile is saved
**only after it connects successfully**, so an invalid profile is never stored. Any
previously saved profile is cleared the moment you upload a new file. Once saved, a
**Reconnect with saved profile** button appears in the web UI
(`http://localhost:35001`) — click it to re-run the SAML login without
re-uploading the file.

- `docker compose` sets `SAVE_PROFILE: "true"` (see `compose.yml`).
- `docker run` — add `-e SAVE_PROFILE=true`.

To keep the saved profile across container recreation, mount a volume at `/data`:

- `docker compose` already declares the `vpn_data` volume.
- `docker run` — add `-v vpn-data:/data`.

Without a `/data` volume the saved profile still survives `docker restart`, but is
lost when the container is removed/recreated.

### Auto-reconnect on visit

Set `AUTO_RECONNECT` (`1`/`true`/`yes`/`on`) to skip the button: after a session
that was connected and then dropped (e.g. the SAML session expired), the next visit
to the web UI re-runs auth automatically, as if you had clicked Reconnect.

- `docker compose` sets `AUTO_RECONNECT: "true"` (see `compose.yml`).
- `docker run` — add `-e AUTO_RECONNECT=true`.

It fires **only** for a session that dropped after being connected in the running
container. It deliberately does **not** fire on a fresh container start, after a
restart, or when the profile is invalid (auth never succeeded) — in those cases you
connect/reconnect manually. Pair it with a mounted profile or `SAVE_PROFILE` so a
profile is available to reconnect from.

## Custom OpenVPN hooks

OpenVPN runs internal hook scripts on connect/disconnect. Each one calls, in order:

1. the alpine package script (DNS setup on `up`, restore on `down`),
2. **your** script, if present at the reserved path below and executable,
3. the connect/disconnect event the web UI listens for.

Drop your own logic in any of these reserved paths — all optional, run only if
present and executable:

| Reserved path | Runs when | Typical use |
| --- | --- | --- |
| `/etc/openvpn/up.sh` | tunnel is up (after DNS) | extra setup |
| `/etc/openvpn/down.sh` | tunnel is going down | cleanup |
| `/etc/openvpn/route-up.sh` | routes are installed | add/adjust routes |
| `/etc/openvpn/route-pre-down.sh` | before routes are torn down | undo route changes |

Your script must be executable (mode `0555`/`+x`). It receives OpenVPN's usual
environment (`dev`, `route_net_gateway`, `foreign_option_*`, …). Don't emit the
connect/disconnect event yourself — the container already does.

Provide a script either by bind-mounting a file or, with `docker compose`, by
inlining it as a config (no extra files):

```yaml
services:
  vpn:
    configs:
      - source: route_up
        target: /etc/openvpn/route-up.sh
        mode: 0555            # must be executable

configs:
  route_up:
    content: |
      #!/bin/sh
      echo "route-up ran, gateway is $$route_net_gateway"
```

> In compose `content:`, escape every `$` as `$$` so compose doesn't interpolate
> it — the script receives a single `$`.

### Example: reach the container over your LAN (proxy use case)

Run an HTTP proxy inside the VPN's network namespace (e.g. tinyproxy with
`network_mode: "service:vpn"`) and use it from other machines on your LAN, so
their traffic exits through the VPN. When the VPN takes over the default route,
replies to LAN clients would be sent into the tunnel and lost. Pin your LAN
subnet(s) back to the local gateway with a `route-up.sh` hook:

```sh
#!/bin/sh
# Keep LAN clients able to reach the proxy after the VPN takes the default route.
# Set LAN_SUBNET in the environment (space-separated for multiple subnets).
if [ -n "$LAN_SUBNET" ]; then
	# LAN gateway + interface = the default route that is NOT the VPN tunnel
	DEF="$(ip route show default | awk '$5 !~ /^tun/ {print; exit}')"
	GW="$(echo "$DEF" | awk '{print $3}')"
	DEV="$(echo "$DEF" | awk '{print $5}')"
	if [ -n "$GW" ] && [ -n "$DEV" ]; then
		for net in $LAN_SUBNET; do
			ip route add "$net" via "$GW" dev "$DEV" || true
			echo "Added LAN route $net via $GW dev $DEV"
		done
	fi
fi
```

The proxy's own upstream requests still egress through the VPN — only replies to
the original LAN clients are pinned to the local interface. `compose.yml` ships
this exact example, inlined as the `route_up` config and driven by a `LAN_SUBNET`
env var (set it to your clients' subnet, e.g. `192.168.10.0/24`). It needs no
extra packages — `ip` is provided by the base image's busybox.

## Multi-arch publishing
GitHub Actions publishes a multi-platform image from `.github/workflows/docker-publish.yml`.

On pushes to `master` and version tags, the workflow builds and publishes:

- `linux/amd64`
- `linux/arm64`

The workflow publishes to `ghcr.io/<owner>/aws-vpn-client`. A push to `master` publishes the `:master` image tag. A push of a Git tag like `v1.2.3` publishes both `:v1.2.3` and `:latest`. Pull requests run the same multi-arch build without pushing.
