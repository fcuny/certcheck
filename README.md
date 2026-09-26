# certcheck

At this point it's pretty clear that I'll never remember the syntax for
`opensll` to show various information about a certificate.

## Installation

```
go install fcuny.net/certcheck@latest
```

## Usage

```
certcheck badssl.com

certcheck go run . -domain badssl.com -port 443 -format long

certcheck -domain self-signed.badssl.com -insecure -format long

certcheck -domain badssl.com -timeout 5s

certcheck -domain badssl.com -warn-days 14
```

`-warn-days N` (default `0`, disabled) makes certcheck exit with status `2`
instead of `0` when the certificate's remaining validity is `N` days or
fewer (including already expired). Status `1` is still reserved for hard
errors such as connection or parsing failures.

## Notes

Could the same be achieved with a wrapper around `openssl` ? yes.
