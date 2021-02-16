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

### Installation

You can install drsh locally using `go get`. 
Make sure you are using go version 1.13+.

```
go get -u -v github.com/dmhacker/drsh/cmd/drsh
```

You can also update drsh using the same command.

Try generating a default configuration file using the following:

```
drsh config
```

### Configuration

Both servers and clients on the same machine use only one config located
at `$XDG_CONFIG_HOME/drsh/config.yml`. For the majority of users, this
will expand to `$HOME/.config/drsh/config.yml`.

The config is structured in two parts, a server section and a client section.

* The server section has a `hostname` and `redisuri` field. The URI specifies
the Redis node that the server should connect to. The hostname specifies what
the machine's unique name in the network is.
* The client section has an `aliases` section, which can optionally consists of
zero or more aliases. An alias represents a username/hostname/uri combination
in shorthand. Rather than entering the full combination every time a client
wants to log into a specific server, they can instead just type in the alias.
This is similar to how aliases work in SSH.

Please also note that while servers can be run as root and have access to
logins as root, the practice of logging in as a root as a client is **explicitly
forbid**. Unlike SSH, there is no option to enable this functionality.

### Servers

Running the server is simple.

```
drsh serve
```

Use the `-h` flag for help.

### Clients

Connecting to a server is also simple.

```
drsh connect {ALIAS|USER@HOST@URI}
```

For example, with the default config, the following commands are equivalent.

```
drsh connect $USER-$HOST
drsh connect $USER@$HOST@redis://localhost:6379
```

There is also a ping command that measures the latency between a client and
server, with the packets passing through Redis.

```
drsh ping {ALIAS|USER@HOST@URI}
```

Again, use the `-h` flag for help.

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
