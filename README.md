# Quay Token Client

A command-line client for manipulating quay service tokens. This project is a playground to demonstrate the possibilities.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
  - [Command-line Flags and Environment Variables](#command-line-flags-and-environment-variables)
  - [Examples](#examples)
- [License](#license)

## Installation

To install the `quay-token-client`, ensure you have Go installed (version 1.24 or higher recommended).

```bash
go install github.com/knrc/quay-token-client@latest
```

This will install the executable in your `$GOPATH/bin` directory. Make sure `$GOPATH/bin` is in your system's `PATH`.

Alternatively, you can clone the repository and build from source:

```bash
git clone https://github.com/knrc/quay-token-client.git
cd quay-token-client
go build -o quay-token-client ./cmd/quay-token-client
```

## Usage

Once installed, you can use the `quay-token-client` command.

### Command-line Flags and Environment Variables

The `quay-token-client` supports various command-line flags and can also be configured using environment variables. Environment variables are prefixed with `QUAY_`.

Here are the available flags:

-   `--quay-url`, `-q` (string): Quay URL (e.g., `https://quay.io/repository/`). Can also be set via `QUAY_QUAY_URL`.
-   `--username`, `-u` (string): Quay admin username. Can also be set via `QUAY_USERNAME`.
-   `--password`, `-p` (string): Quay admin password. Can also be set via `QUAY_PASSWORD`.
-   `--service-name`, `-s` (string, **required**): Name of the service for the key. Can also be set via `QUAY_SERVICE_NAME`.
-   `--key-id`, `-k` (string, **required**): ID for the new service key; should be unique otherwise old versions may be retrieved from the cache. Can also be set via `QUAY_KEY_ID`.
-   `--expiry`, `-e` (duration): Expiry of the service key, defaults to no-expiry. Can also be set via `QUAY_EXPIRY`.
-   `--delete`, `-d` (bool): Delete token after approval. Can also be set via `QUAY_DELETE`.
-   `--test-docker`, `-t` (bool): Test Docker V2 token generation and repository listing. Can also be set via `QUAY_TEST_DOCKER`.

### Examples

The basic usage involves providing the Quay URL, admin credentials, service name, and key ID:

```bash
quay-token-client --quay-url https://your-quay.com \
                  --username admin --password password \
                  --service-name test-service --key-id test-key
```

You can also use environment variables:

```bash
export QUAY_QUAY_URL=https://your-quay.com
export QUAY_USERNAME=admin
export QUAY_PASSWORD=password
export QUAY_SERVICE_NAME=test-service
export QUAY_KEY_ID=test-key
quay-token-client
```

To delete a service key after approval:

```bash
quay-token-client ... --delete
```

To test Docker V2 token generation and repository listing:

```bash
quay-token-client ... --test-docker
```

## License

This project is open-source and licensed under the [Apache License, Version 2.0](https://opensource.org/license/apache-2-0).
