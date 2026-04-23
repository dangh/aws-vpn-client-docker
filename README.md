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
2. Run `docker run --name vpn -d --net host -v /path/to/profile.ovpn:/opt/openvpn/profile.ovpn:ro --device /dev/net/tun:/dev/net/tun --cap-add NET_ADMIN ghcr.io/dangh/aws-vpn-client:latest`
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

### Multi-arch publishing
GitHub Actions publishes a multi-platform image from `.github/workflows/docker-publish.yml`.

On pushes to `master` and version tags, the workflow builds and publishes:

- `linux/amd64`
- `linux/arm64`

The workflow publishes to `ghcr.io/<owner>/aws-vpn-client`. A push to `master` publishes the `:master` image tag. A push of a Git tag like `v1.2.3` publishes both `:v1.2.3` and `:latest`. Pull requests run the same multi-arch build without pushing.
