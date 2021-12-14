# wgstarman

WireGuard manager written in Python 3 to connect two or more peers in a star VPN, i.e. having a central peer which routes the traffic within the VPN. It includes a DHCP-like IP address allocation mechanism.

It currently supports IPv6 only, but IPv4 is in the plans (it needs a proper IP address release logic).

It has been designed and tested on Linux, specifically due to the paths and commands used, but it should work on any POSIX / UNIX operating systems (like MacOS).

## Software requirement

- WireGuard kernel's module (it should be enabled by default)
- `wg-quick` command (provided by most Linux distributions via the `wireguard-tools` package)

## Setting up the server

```bash
wgstarman server --ipv6-network fdxx:xxxx:xxxx:yyyy:zzzz:zzzz::/64
                 [--device-name wg0]
                 [--listen-address-4 0.0.0.0]
                 [--listen-address-6 ::]
                 [--listen-port 1194]
                 [--enable-listen-ipv6]
                 [--refresh-psk]
                 [--debug]
```

- `--ipv6-network` the IPv6 network to use for the VPN, i.e. fdxx:xxxx:xxxx:yyyy:zzzz:zzzz::/64
- `--device-name` the name of both the network device and the configuration file (default: wg0)
- `--listen-address-4` the address IPv4 on which the address manager will listen on (default: 0.0.0.0)
- `--listen-address-6` the address IPv6 on which the address manager will listen on; requires `--enable-listen-ipv6` (default: ::)
- `--listen-port` the port on which WireGuard (UDP) and the address manager (TCP) will listen on (default: 1194)
- `--enable-listen-ipv6` enable address manager to listen on `{listen_address_6}:{listen_port}`
- `--refresh-psk` force the refresh of the pre-shared key
- `--debug` enable debug log

The manager will output the pre-shared key (PSK), to be used for interacting with it and connect new peers.

The central peer will assign to itself the first IP of the network.

**NOTE**: the pre-shared key is being stored in `/etc/wgstarman/wgstarman.conf` and is formatted in the following way:

`{server_public_key} = {pre-shared key}`

The server's public key is generated at runtime the first time the network is being configured.

### sysctl configurations

The following sysctl configurations must be set:

- `net.ipv6.conf.all.disable_ipv6=0` to enable IPv6 addresses
- `net.ipv6.conf.all.forwarding=1` to allow the packets routing via IPv6

### docker caps

In case the server is run in docker, the following caps must be set:

- `NET_ADMIN`
- `SYS_MODULE`

## Setting up the peers

```bash
wgstarman peer --server-address xx.yy.zz.kk
               [--server-port 1194]
               --device-name wg0
               --psk ODjCtWVtBzAq11clgtEwYxhHfEz8asGmnzwEQsqIZTU=
               [--keep-alive]
               [--overwrite]
               [--debug]
```

- `--server-address` the server's public IP (either IPv4 or IPv6)
- `--server-port` (default 1194) the port on which the server is listening (see server configuration)
- `--device-name` the device and configuration file WireGuard will use for this VPN
- `--psk` the pre-shared key, given by the server at startup
- `--keep-alive` keep the connection to the server alive (to avoid connection drop in case of NAT)
- `--overwrite` overwrite if a configuration already exists
- `--debug` enable debug log

Once the command is given and throws no errors, a configuration file is being written in `/etc/wireguard/[device-name].conf` and the connection is established; the VPN connection can thus be upped or downed via the `wg-quick` commands.

In case `wgstarman` is used again specifying an already configured device name, it will connect to the `wgstarman` server again and verify its address / public key against the server's configuration: in case the server doesn't have the peer's record, it will assign a new IP and the peer will overwrite its own configuration.