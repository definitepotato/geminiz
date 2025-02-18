# Not for production use

This is a learning project.

Generate private key `openssl genpkey -algorithm RSA -out key.pem`
Generate self-signed cert using private key `openssl req -new -x509 -key key.pem -out cert.pem -days 365`

Build `zig build`

Make sure **cert.pem** and **key.pem** are in the same dir as the **gemini** binary in **zig-out/bin**

Run `./gemini` from **zig-out/bin** dir

Run `socat - OPENSSL:localhost:8443,verify=0` and press enter twice to observe results
