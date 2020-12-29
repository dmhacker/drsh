# drsh

drsh stands for David's Remote SHell. It was intended as a personal project
and a supplement to ssh, designed to add some additional functionality that
I needed for some servers.

Normally, a client establishes a SSH connection with a server by opening a 
secure connection to the port that the server's SSH daemon is listening on, 
usually port 22. If the server is behind a firewall, then the firewall
has to have this port open in order to allow SSH traffic to arrive from
an external client. This could be dangerous, especially if the port is later
re-assigned to another application.

drsh's solution to this problem is to have the client and the server both
route their packets through an Redis instance. This eliminates the need 
for the server to allow inbound connections, because it receives messages 
through an outbound connection to the Redis instance. The only necessary 
condition is that the client and  server must both be able to connect 
to a mutually agreed upon Redis node.

## Setup

### Configuration

Both servers and clients on the same machine use only one config located
at `$XDG_CONFIG_HOME/drsh/config.yml`. For the majority of users, this
will expand to `$HOME/.config/drsh/config.yml`.

An example config has been provided in this repository.
It is recommended that you download this to the above location using
the following commands:

```
[[ -z "${XDG_CONFIG_HOME}" ]] && XDG_CONFIG_HOME="${HOME}/.config"
mkdir -p "${XDG_CONFIG_HOME}/drsh"
curl -sL -o "${XDG_CONFIG_HOME}/drsh" https://raw.githubusercontent.com/dmhacker/drsh/main/config.yml
```

The config is structured in two parts, a server section and a client section.

The server section has a Hostname and RedisUri field. The RedisUri specifies
the Redis node that the server should connect to. The Hostname specifies what
the machine's unique name in the network is.

The client section has an Aliases section, which can optionally consists of
zero or more aliases. An alias represents a username/hostname/uri combination
in shorthand. Rather than entering the full combination every time a client
wants to log into a specific server, they can instead just type in the alias.
This is similar to how aliases work in SSH.

The default config assumes that the server connects to a Redis node hosted
locally, has the hostname 'default', and can run with the permissions of 
user 'ubuntu'. In practice, one would probably want to connect to a Redis
node in the cloud, as that would be a more accessible option.

Please also note that while servers can be run as root and have access to
logins as root, the practice of logging in as a root as a client is explicitly
forbid. Unlike SSH, there is no option to enable this functionality.

### Installation

TODO: This will be completed when drsh is able as a package

### Servers

Running the server is simple:

```
go get github.com/dmhacker/drsh serve
```

Use the `-h` flag for a list of additional options.

### Clients

Connecting to a server is also simple:

```
go get github.com/dmhacker/drsh connect {ALIAS|USER@HOST@URI}
```

For example, with the default config, the following commands are equivalent:

```
go get github.com/dmhacker/drsh connect ubuntu-default
go get github.com/dmhacker/drsh connect ubuntu@default@redis://localhost:6379
```

There is also a ping command that measures the latency between a client and
server, with the packet and response passing through Redis. Functions
the same as above:

```
go get github.com/dmhacker/drsh ping {ALIAS|USER@HOST@URI}
```

## Caveats

There are several important reasons why you should not use this in a real 
world setting:
* drsh assumes that all clients & servers connecting to one Redis instance are
mutually trusted. That is, if a user joins a Redis instance, they can freely log on
to any server connected to the same Redis node.
* drsh tries to implement forward secrecy using the Diffie-Helman key exchange
and to encrypt messages using the ChaCha20-Poly1305 AEAD cipher. However, I cannot
guarantee that my implementation is cryptographically secure.
* There are significant performance losses associated with routing packets
through an intermediary rather than through a direct route.

As the project matures, these concerns will be addressed by
additional improvements and bug fixes.
