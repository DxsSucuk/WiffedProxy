# Wiffed Proxy
A simple TCP and UDP reverse Proxy meant to be used for things like Minecraft Servers, FiveM or even Websites.

## Features
- [x] Hostname routing (SNI) (UNTESTED)
- [x] Hostname routing (Minecraft Handshake) (UNTESTED)
- [x] Hostname routing (HTTP) (UNTESTED)
- [ ] Automatic Service detection
- [ ] Manual Service detection (is HTTP or is Minecraft)
- [x] Port routing (25565 -> 10.0.0.12:25565)
- [x] Proxy Protocol V2 support (UNTESTED WITH MC, C-T FUNCTIONAL!)
- [x] Real-IP Header for HTTP

### UNTESTED what does that mean?
That the given feature has been programmed based on the given schematics of for example the Minecraft Handshake Packet.<br>
But not really tested at all.

### C-T FUNCTIONAL what does that mean?
The given feature has been tested against a custom server-client solution, like a simple Java Client -> Server echo project.<br>
And it has worked as expected.