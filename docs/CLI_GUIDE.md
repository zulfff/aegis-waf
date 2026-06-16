# CLI Command Reference

## Global Flags

```
aegis-waf [GLOBAL FLAGS] <COMMAND> [ARGS]
```

| Flag             | Short | Environment Var      | Default                       | Description            |
| ---------------- | ----- | -------------------- | ----------------------------- | ---------------------- |
| `--config`       | `-c`  | `AEGIS_CONFIG`       | `/etc/aegis-waf/config.toml`  | Config file path       |
| `--log-level`    | `-l`  | `AEGIS_LOG_LEVEL`    | `info`                        | Log verbosity          |
| `--log-format`   |       | `AEGIS_LOG_FORMAT`   | `json`                        | `json` or `text`       |
| `--version`      | `-V`  | -                    | -                             | Print version and exit |
| `--help`         | `-h`  | -                    | -                             | Print help             |

## Commands

### `run`

Start the WAF server.

```bash
aegis-waf run [OPTIONS]
```

| Option              | Type   | Default | Description              |
| ------------------- | ------ | ------- | ------------------------ |
| `--config`          | string | -       | Config file path         |
| `--tls-cert`        | string | -       | Override TLS cert path   |
| `--tls-key`         | string | -       | Override TLS key path    |

**Example:**

```bash
aegis-waf run --config /etc/aegis-waf/config.toml
aegis-waf run --tls-cert /custom/cert.pem --tls-key /custom/key.pem
```

---

### `init`

Generate a default configuration file.

```bash
aegis-waf init [OPTIONS]
```

| Option        | Short | Default | Description                  |
| ------------- | ----- | ------- | ---------------------------- |
| `--output`    | `-o`  | stdout  | Write config to file         |
| `--force`     | `-f`  | false   | Overwrite existing file      |
| `--with-tls`  |       | false   | Generate self-signed cert    |

**Example:**

```bash
aegis-waf init --output /etc/aegis-waf/config.toml
aegis-waf init --with-tls --output ./config.toml
```

---

### `healthcheck`

Check if the running server is healthy. Returns exit code 0 for healthy.

```bash
aegis-waf healthcheck [OPTIONS]
```

| Option          | Default                 | Description            |
| --------------- | ----------------------- | ---------------------- |
| `--url`         | `http://localhost:9090` | Metrics endpoint URL   |
| `--timeout`     | `5`                     | Request timeout (secs) |

**Example:**

```bash
aegis-waf healthcheck
aegis-waf healthcheck --url https://remote:9090 --timeout 10
```

---

### `validate`

Validate configuration and rule files without starting the server.

```bash
aegis-waf validate [OPTIONS]
```

| Option        | Short | Description                        |
| ------------- | ----- | ---------------------------------- |
| `--config`    | `-c`  | Config file path                   |
| `--rules`     | `-r`  | Additional rules file to validate  |

**Example:**

```bash
aegis-waf validate
aegis-waf validate --config prod.toml --rules custom-rules.toml
```

**Exit codes:**

| Code | Meaning                        |
| ---- | ------------------------------ |
| 0    | Configuration is valid         |
| 1    | Invalid config or rules        |
| 2    | File not found / cannot read   |

---

### `reload`

Send a graceful reload signal to a running instance.

```bash
aegis-waf reload [OPTIONS]
```

| Option       | Default                  | Description              |
| ------------ | ------------------------ | ------------------------ |
| `--pid-file` | `/var/run/aegis-waf.pid` | PID file path            |
| `--signal`   | `hup`                    | Signal: `hup` or `usr1`  |

**Example:**

```bash
aegis-waf reload
sudo systemctl reload aegis-waf
```

---

### `version`

Print version information.

```bash
aegis-waf version [OPTIONS]
```

| Option     | Short | Description                     |
| ---------- | ----- | ------------------------------- |
| `--json`   | `-j`  | Output as JSON                  |
| `--verbose`| `-v`  | Include build info and features |

**Example output:**

```
aegis-waf 1.0.0 (commit: a1b2c3d, built: 2025-01-15)
target: x86_64-unknown-linux-gnu
features: default
```

---

### `bench`

Run a local performance benchmark against the WAF.

```bash
aegis-waf bench [OPTIONS]
```

| Option          | Default                 | Description                  |
| --------------- | ----------------------- | ---------------------------- |
| `--url`         | `https://localhost:8443`| Target URL                   |
| `--connections` | `10`                    | Concurrent connections       |
| `--duration`    | `30`                    | Test duration (seconds)      |
| `--insecure`    | false                   | Skip TLS verification        |
| `--output`      | -                       | Write results to file (JSON) |

**Example:**

```bash
aegis-waf bench --connections 50 --duration 60
aegis-waf bench --url https://my-waf:8443 --insecure
```

---

### `migrate`

Migrate configuration from v0.x to v1.x format.

```bash
aegis-waf migrate [OPTIONS]
```

| Option     | Short | Description                     |
| ---------- | ----- | ------------------------------- |
| `--input`  | `-i`  | Path to old config file         |
| `--output` | `-o`  | Write migrated config to file   |
| `--dry-run`|       | Preview changes without writing |

---

### `keygen`

Generate keys for JWT signing or internal encryption.

```bash
aegis-waf keygen [OPTIONS]
```

| Option      | Short | Default  | Description                |
| ----------- | ----- | -------- | -------------------------- |
| `--type`    | `-t`  | `jwt`    | Key type: `jwt` or `aes`  |
| `--bits`    | `-b`  | `256`    | Key size in bits           |
| `--output`  | `-o`  | stdout   | Write key to file          |

**Example:**

```bash
aegis-waf keygen --type jwt --output jwt-secret.key
aegis-waf keygen --type aes --bits 256
```

---

## Signal Handling

| Signal      | Action                                  |
| ----------- | --------------------------------------- |
| `SIGTERM`   | Graceful shutdown (wait for drain)      |
| `SIGINT`    | Graceful shutdown (Ctrl+C)              |
| `SIGHUP`    | Reload configuration and rules          |
| `SIGUSR1`   | Reopen log files (log rotation)         |
| `SIGUSR2`   | Dump connection state to stderr         |

## Environment Variables

| Variable               | Description                         |
| ---------------------- | ----------------------------------- |
| `AEGIS_CONFIG`         | Config file path                    |
| `AEGIS_LOG_LEVEL`      | Log level override                  |
| `AEGIS_LOG_FORMAT`     | Log format override                 |
| `AEGIS_ADMIN_API_KEY`  | Admin API key                       |
| `AEGIS_JWT_SECRET`     | JWT signing secret                  |
| `RUST_LOG`             | Rust tracing filter directive       |
| `RUST_BACKTRACE`       | Enable backtrace on panic           |

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
aegis-waf completions bash > /etc/bash_completion.d/aegis-waf

# Zsh
aegis-waf completions zsh > /usr/local/share/zsh/site-functions/_aegis-waf

# Fish
aegis-waf completions fish > ~/.config/fish/completions/aegis-waf.fish
```
