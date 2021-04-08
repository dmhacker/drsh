# drsh

drsh stands for David's Remote SHell. It is a custom implementation of
a remote shell protocol that routes all traffic through a mutually agreed upon 
Redis instance rather than directly from client to server. One might describe 
drsh as a variant of [ssh](https://www.openssh.com/) specifically designed 
with the functionality of [ngrok](https://ngrok.com/).

More about drsh:
* All clients & servers connecting to one Redis instance are assumpted to be mutually 
trusted. That is, if a user can access a Redis instance, they can freely log on
to any server connected to the same Redis node.
* However, once a secure channel has be set up between a specific client and server,
any content passing through the channel cannot be inspected by other parties on the
instance, as all subsequent messages past the handshake are encrypted.
* Forward secrecy is implemented by generating ephemeral keys from secure randomness.
* Keys are exchanged using the Diffie-Helman key exchange algorithm.
* Messages are encrypted using the ChaCha20-Poly1305 AEAD cipher.

## Setup

### Installation

You can install drsh locally using `go get`. 
Make sure you are using go version 1.13+.

```
GO111MODULE=on go get -v github.com/dmhacker/drsh/cmd/drsh@latest
```

You can also update drsh using the same command.

Try generating a default configuration file using the following:

```
drsh config
```

### Configuration

Both servers and clients on the same machine use only one config located
at `$HOME/.drsh/config.yml`. This location can be changed using the `--config` option.

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
drsh login {ALIAS|USER@HOST@URI}
```

For example, with the default config, the following commands are equivalent.

```
drsh login $USER-$HOST
drsh login $USER@$HOST@redis://localhost:6379
```

Additionally, files can be uploaded to and downloaded from the server.

```
drsh upload {ALIAS|USER@HOST@URI} {LOCAL_FILE} {REMOTE_FILE}
drsh download {ALIAS|USER@HOST@URI} {REMOTE_FILE} {LOCAL_FILE}
```

There is also a ping command that measures the latency between a client and
server, with the packets passing through Redis.

```
drsh ping {ALIAS|USER@HOST@URI}
```

Again, use the `-h` flag for help.
