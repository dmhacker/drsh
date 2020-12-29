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

TODO: Commands will be provided here when the project is more functional

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
