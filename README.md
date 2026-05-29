# veramo-mock-as

Mock OAuth2 / OpenID authorization server used by the [irmago](https://github.com/privacybydesign/irmago)
OpenID4VCI integration tests against the [veramo-agent](https://github.com/uport-project/veramo) issuer.

It implements just enough of the OAuth2 / OpenID spec to complete an authorization-code flow
against the issuer; there is no real login, no signature verification, and no persistence.
The server is intended for tests only — do not deploy it.

## Endpoints

| Route                                       | Method | Purpose                                                       |
| ------------------------------------------- | ------ | ------------------------------------------------------------- |
| `/.well-known/oauth-authorization-server`   | GET    | OAuth2 discovery metadata                                     |
| `/.well-known/openid-configuration`         | GET    | OpenID discovery metadata (same payload as above)             |
| `/jwks`                                     | GET    | Empty JWK Set (signatures are not checked)                    |
| `/authorize`                                | GET    | Issues an auth code (302 to `redirect_uri`, or JSON if absent) |
| `/token`                                    | POST   | Exchanges an auth code for an access token                    |
| `/introspect`                               | POST   | Validates a token and returns the associated `issuer_state`   |

## Configuration

| Variable       | Default                  | Purpose                                       |
| -------------- | ------------------------ | --------------------------------------------- |
| `LISTEN_ADDR`  | `0.0.0.0:9090`           | Address the server binds to                   |
| `EXTERNAL_URL` | `http://localhost:9090`  | URL that wallets/clients use to reach the server |

## Running

```sh
docker run --rm -p 9090:9090 ghcr.io/privacybydesign/veramo-mock-as:latest
```

Or build from source:

```sh
go build -o mock-as .
./mock-as
```
