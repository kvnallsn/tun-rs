# tun-rs

Platform-agnostic library for interacting with TUN (Layer 3) devices

## Usage
Add the following to your Cargo.toml

```toml
[dependencies]
tun-rs = "0.1"
```

## Features

`tun-rs` supports the following feature flags.

### Default Features:
* `channel`

### Feature List
| Name      | Description                                                      |
| --------- | ---------------------------------------------------------------- |
| `channel` | Enable `crossbeam-channel` based tun device (useful for testing) |

## Examples

See the [examples](examples/) directory for source code

| Name         | Description                                                           |
| ------------ | --------------------------------------------------------------------- |
| echo\_udp.rs | Echos any udp packet sent to this tunnel device (or any ip it routes) |
| tcplog.rs    | Prints information about TCP packets sent to this tunnel device       |

## Platforms

| Platform     | Support | Notes                           |
| ------------ | ------- | ------------------------------- |
| Linux        | Yes     | Tested on Debian 11 (Bullseye)  |
| Mac OS X     | TBD     |                                 |
| FreeBSD      | TBD     |                                 |
| OpenBSD      | TBD     |                                 |
| Windows      | TBD     |                                 |

## License

Copyright 2021 Kevin Allison

Permission is hearby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
