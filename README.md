# DTLShps [![DTLShps](https://img.shields.io/badge/zjw1111-DTLShps-gray.svg?longCache=true&colorB=brightgreen)][Zhang_Jiawei] [![LICENSE](https://img.shields.io/badge/license-AGPL3.0-yellow.svg)](LICENSE) [![Go Reference](https://pkg.go.dev/badge/github.com/zjw1111/DTLShps.svg)](https://pkg.go.dev/github.com/zjw1111/DTLShps)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fzjw1111%2FDTLShps.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fzjw1111%2FDTLShps?ref=badge_shield)

This is a simple implement and verification of DTLShps protocol based on **[pion/dtls][pion/dtls]** and **[DTLShps: SDN-based DTLS handshake protocol simplification for IoT][DTLShps]**

[pion/dtls]: https://github.com/pion/dtls
[DTLShps]: https://doi.org/10.1109/JIOT.2020.2967464

## License
GNU AGPL3.0 License - see [LICENSE](LICENSE) for full text


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fzjw1111%2FDTLShps.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fzjw1111%2FDTLShps?ref=badge_large)

### **Note!!**
This project uses GNU AGPL3.0 LICENSE. If you copy the source code and use it for secondary creation (such as **copying or modifying the code for submitting the homework in college**, etc.), you need to mark the original author's information and mark the modification of the code. For more information, please see the [`LICENSE`](LICENSE) file. If you want to use the code in academic research, please contact me by GitHub issue.

请注意：本项目使用AGPL3.0协议，如果复制源代码并用于二次创作（如**对代码进行拷贝或修改后进行作业提交**等）需标注原作者信息，并标注对代码的修改之处所在。详细信息请看[`LICENSE`](LICENSE)文件。如果你想在学术研究中使用这份代码，请通过GitHub issue联系我。

## Introduction for DTLShps
DTLShps is a simplified handshake protocol of DTLS to reduce the computational overhead of the IoT devices for a general scenario of end-to-end communications based on software-defined networking (SDN).

DTLShps is designed by Yan Ma, Lei Yan, etc in paper [DTLShps: SDN-based DTLS handshake protocol simplification for IoT][DTLShps].

The implementation of DTLShps is divided into two parts: the client/server and the controller, which are completed by [Zhang Jiawei][Zhang_Jiawei] and Ye Lingyun (students in bupt) respectively.

This project is the code of the client/server part, and the author is [Zhang Jiawei][Zhang_Jiawei].

The code of the controller part was completed by Ye Lingyun, which is not open source now.

[Zhang_Jiawei]: https://github.com/zjw1111

## What I do
- define the format of new messages
    - Handshake messages types: \
    **MESSAGE FORMAT**: one byte for length and some bytes for message
        - EncryptedKey - 31
        - Identity - 32
    - Alert types:
        - NoEncryptedKey - 101
        - NoIdentity - 102
- modify the cipher suite method and flight generation and parse method
- implement a DTLShps example program

## How to use it
At first, you need to create your certificates. (Of course, you can also use existing certificates)

Then, you need to run the server and client. You can use parameter `-h` or `--help` to see all the options.

In particular, you can use parameter `-t` to send the DTLShps packets without the controller and run the DTLShps server and client for test.

```sh
cd examples/DTLShps
go run server/server.go
```

```sh
cd examples/DTLShps
go run client/client.go
```

## The ORIGIN README
I fork the repo based on the version of [pion/dtls#9610016](https://github.com/pion/dtls/tree/96100166cd996c9b0d5a594740a15102bbf8fef7). And then is the origin readme file of [pion/dtls][pion/dtls].

> <h1 align="center">
>   <br>
>   Pion DTLS
>   <br>
> </h1>
> <h4 align="center">A Go implementation of DTLS</h4>
> <p align="center">
>   <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-dtls-gray.svg?longCache=true&colorB=brightgreen" alt="Pion DTLS"></a>
>   <a href="https://sourcegraph.com/github.com/pion/dtls"><img src="https://sourcegraph.com/github.com/pion/dtls/-/badge.svg" alt="Sourcegraph Widget"></a>
>   <a href="https://pion.ly/slack"><img src="https://img.shields.io/badge/join-us%20on%20slack-gray.svg?longCache=true&logo=slack&colorB=brightgreen" alt="Slack Widget"></a>
>   <br>
>   <a href="https://travis-ci.org/pion/dtls"><img src="https://travis-ci.org/pion/dtls.svg?branch=master" alt="Build Status"></a>
>   <a href="https://pkg.go.dev/github.com/pion/dtls"><img src="https://godoc.org/github.com/pion/dtls?status.svg" alt="GoDoc"></a>
>   <a href="https://codecov.io/gh/pion/dtls"><img src="https://codecov.io/gh/pion/dtls/branch/master/graph/badge.svg" alt="Coverage Status"></a>
>   <a href="https://goreportcard.com/report/github.com/pion/dtls"><img src="https://goreportcard.com/badge/github.com/pion/dtls" alt="Go Report Card"></a>
>   <a href="https://www.codacy.com/app/Sean-Der/dtls"><img src="https://api.codacy.com/project/badge/Grade/18f4aec384894e6aac0b94effe51961d" alt="Codacy Badge"></a>
>   <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
> </p>
> <br>
> 
> Native [DTLS 1.2][rfc6347] implementation in the Go programming language.
> 
> A long term goal is a professional security review, and maybe an inclusion in stdlib.
> 
> ### Goals/Progress
> This will only be targeting DTLS 1.2, and the most modern/common cipher suites.
> We would love contributions that fall under the 'Planned Features' and any bug fixes!
> 
> #### Current features
> * DTLS 1.2 Client/Server
> * Key Exchange via ECDHE(curve25519, nistp256, nistp384) and PSK
> * Packet loss and re-ordering is handled during handshaking
> * Key export ([RFC 5705][rfc5705])
> * Serialization and Resumption of sessions
> * Extended Master Secret extension ([RFC 7627][rfc7627])
> 
> #### Supported ciphers
> 
> ##### ECDHE
> * TLS_ECDHE_ECDSA_WITH_AES_128_CCM ([RFC 6655][rfc6655])
> * TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ([RFC 6655][rfc6655])
> * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ([RFC 5289][rfc5289])
> * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ([RFC 5289][rfc5289])
> * TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ([RFC 8422][rfc8422])
> * TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA ([RFC 8422][rfc8422])
> 
> ##### PSK
> * TLS_PSK_WITH_AES_128_CCM ([RFC 6655][rfc6655])
> * TLS_PSK_WITH_AES_128_CCM_8 ([RFC 6655][rfc6655])
> * TLS_PSK_WITH_AES_128_GCM_SHA256 ([RFC 5487][rfc5487])
> * TLS_PSK_WITH_AES_128_CBC_SHA256 ([RFC 5487][rfc5487])
> 
> [rfc6347]: https://tools.ietf.org/html/rfc6347
> [rfc5705]: https://tools.ietf.org/html/rfc5705
> [rfc7627]: https://tools.ietf.org/html/rfc7627
> [rfc5289]: https://tools.ietf.org/html/rfc5289
> [rfc8422]: https://tools.ietf.org/html/rfc8422
> [rfc6655]: https://tools.ietf.org/html/rfc6655
> [rfc5487]: https://tools.ietf.org/html/rfc5487
> 
> #### Planned Features
> * Chacha20Poly1305
> 
> #### Excluded Features
> * DTLS 1.0
> * Renegotiation
> * Compression
> 
> ### Using
> 
> This library needs at least Go 1.13, and you should have [Go modules
> enabled](https://github.com/golang/go/wiki/Modules).
> 
> #### Pion DTLS
> For a DTLS 1.2 Server that listens on 127.0.0.1:4444
> ```sh
> go run examples/listen/selfsign/main.go
> ```
> 
> For a DTLS 1.2 Client that connects to 127.0.0.1:4444
> ```sh
> go run examples/dial/selfsign/main.go
> ```
> 
> #### OpenSSL
> Pion DTLS can connect to itself and OpenSSL.
> ```
>   // Generate a certificate
>   openssl ecparam -out key.pem -name prime256v1 -genkey
>   openssl req -new -sha256 -key key.pem -out server.csr
>   openssl x509 -req -sha256 -days 365 -in server.csr -signkey key.pem -out cert.pem
> 
>   // Use with examples/dial/selfsign/main.go
>   openssl s_server -dtls1_2 -cert cert.pem -key key.pem -accept 4444
> 
>   // Use with examples/listen/selfsign/main.go
>   openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -debug -cert cert.pem -key key.pem
> ```
> 
> ### Using with PSK
> Pion DTLS also comes with examples that do key exchange via PSK
> 
> 
> #### Pion DTLS
> ```sh
> go run examples/listen/psk/main.go
> ```
> 
> ```sh
> go run examples/dial/psk/main.go
> ```
> 
> #### OpenSSL
> ```
>   // Use with examples/dial/psk/main.go
>   openssl s_server -dtls1_2 -accept 4444 -nocert -psk abc123 -cipher PSK-AES128-CCM8
> 
>   // Use with examples/listen/psk/main.go
>   openssl s_client -dtls1_2 -connect 127.0.0.1:4444 -psk abc123 -cipher PSK-AES128-CCM8
> ```
> 
> ### Contributing
> Check out the **[contributing wiki](https://github.com/pion/webrtc/wiki/Contributing)** to join the group of amazing people making this project possible:
> 
> ### License
> MIT License - see [LICENSE](LICENSE) for full text
>