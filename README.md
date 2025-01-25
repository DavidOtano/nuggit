# nuggit
An ongoing hobby project to build a fully headless WinMX experience that can be self-hosted in a docker container.

## Features
- [x] Handshake Server - Handles WPNP TCP handshakes
- [x] Chat Server - (In active development)
- [ ] Chat Client
- [ ] Peer Cache
- [ ] Secondary Client
- [ ] Primary Server

## Chat Server
- Inspired by WCS and will soon be in full feature parity with it.

## Licensing
- MIT

## Development
This project uses [xmake](https://xmake.io/). The build can also be ran in a docker container.

`$ cd nuggit`  
`$ xmake config -m debug`  
`$ xmake`  

## Special Thanks
- 2sen - WPN Encryption / inspiration from NushiChat
- Bender - WPN Encryption / inspiration from RoboMX
- Krishean Draconis - inspiration from DraconisMX
- King Macro - inspiration from WCS
