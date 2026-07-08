# Service Detection & Fingerprinting

This document describes how PortFootprint fingerprints network services.

## Banner Grabbing Flow
- **Passive read**: Checks the socket immediately after connecting to see if the service prints a welcome string (such as SSH banners or FTP greetings).
- **Active query**: If passive read returns empty bytes, it sends a carriage return probe (`b"\r\n\r\n"`) to provoke a response.

## Protocol Probes

| Protocol | Probe Payload | Expected Metadata |
| -------- | ------------- | ----------------- |
| **HTTP** | `HEAD / HTTP/1.1` / `GET /` | Server header, Title, Powered-By, Location |
| **HTTPS** | TLS Client Handshake | Cipher, TLS version, Certificate fields |
| **SSH** | Passive greeting | Software version, Protocol version |
| **FTP** | Passive greeting + `FEAT` | welcome banner, FTP features list |
| **SMTP** | Passive greeting + `EHLO` | ESMTP extensions, STARTTLS support |
| **DNS** | Binary TCP DNS Query | Valid Transaction ID match |
| **IRC** | `NICK` / `USER` registers | Notice auth strings, Daemon version |
| **Database** | Handshake bytes | MySQL greeting, Postgres SSL, Redis PONG, Mongo Hello |
