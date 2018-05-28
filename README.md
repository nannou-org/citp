# citp [![Build Status](https://travis-ci.org/nannou-org/citp.svg?branch=master)](https://travis-ci.org/nannou-org/citp) [![Crates.io](https://img.shields.io/crates/v/citp.svg)](https://crates.io/crates/citp) [![Crates.io](https://img.shields.io/crates/l/citp.svg)](https://github.com/nannou-org/citp/blob/master/LICENSE-MIT) [![docs.rs](https://docs.rs/citp/badge.svg)](https://docs.rs/citp/)

A pure-rust implementation of CITP aka Controller Interface Transport Protocol.
CITP is an open communications protocol for the integration of visualisers,
lighting consoles and media servers.

## Features

This implementation aims to implement the full CITP protocol as the
specification describes. The spec can be found at
[citp-protocol.org](http://www.citp-protocol.org/viewtopic.php?f=1&p=752&sid=ba74a80bacbb71baa8c655659063cd69#p752).

- The **protocol** module describes all constants and types within the
  specification and provides **WriteBytes** and **ReadBytes** traits for writing
  and reading any of these types to and from arrays of bytes.

  Each layer of the protocol is implemented under its own `protocol` sub-module.
  - [x] `protocol::pinf`
  - [x] `protocol::sdmx`
  - [x] `protocol::fptc`
  - [x] `protocol::fsel`
  - [x] `protocol::finf`
  - [ ] `protocol::msex`

- [ ] The **net** module provides an implementation of the necessary
  broadcasting, multicasting, UDP and TCP streams described within the protocol
  for communication of the protocol over a network.

- **Further Work**:
  - [ ] Types for listening to and iterating over received broadcast/multicast
    messages.
  - [ ] Examples for demonstrating basic usage of each part of the protocol.
  - [ ] Tests that write and then read every type within the protocol to ensure
    correctness of the **WriteToBytes** and **ReadFromBytes** implementations.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


**Contributions**

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
