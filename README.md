# certcheck

At this point it's pretty clear that I'll never remember the syntax for
`opensll` to show various information about a certificate.

## Installation

```
go install fcuny.net/certcheck@latest
```

## Usage

````
certcheck badssl.com

certcheck go run . -domain badssl.com -port 443 -format long

certcheck -domain self-signed.badssl.com -insecure -format long
```

## Notes

Could the same be achieved with a wrapper around `openssl` ? yes.
