# drsh

drsh stands for David's Remote SHell. It was intended as a personal project
and a supplement to ssh, designed to add some additional functionality that
I needed for some servers.

Normally, a client establishes a SSH connection with a server by opening a 
secure connection to the port that the server's SSH daemon is listening on, 
usually port 22. If the server is behind a network firewall, then the firewall
has to have at least 1 port open in order to allow SSH traffic to arrive from
an external client. This could be especially dangerous, especially if the
port is re-assigned to another application later. SSH tunnelling doesn't
necessarily fix the issue either, as even the jump server has to maintain an
open port to itself.

drsh's solution to this problem is to have the client and the server both
route their packets through an intermediate proxy, a Redis instance. This
eliminates the need for the server to allow inbound connections, because
it receives packets through a pool of outbound connections to the Redis
instance. With drsh, the only necessary condition is that the client and 
server must both be able to connect to a mutually agreed upon Redis node.

## Caveats

There are several important reasons why you should not use this in a real 
world setting:
* drsh assumes that all clients & servers connecting to one Redis instance are
mutually trusted. That is, one user won't attempt to interfere with traffic
sent by another node.
* drsh implements forward secrecy using the Diffie-Helman key exchange and
encrypts messages using the ChaCha20-Poly1305 AEAD cipher. However, this
former implementation has not be deemed cryptographically secure by experts.
* There are significant performance losses associated with routing packets
through an intermediary rather than going with a direct route.

Hopefully, as the project matures, these concerns will be addressed by
additional improvements and bug fixes.

## Setup

TODO: Commands will be provided here when the project is more functional
