# Docker Compose deployment

`brainproxy-server serve` behind [Caddy](https://caddyserver.com/), which gets and renews the TLS
certificate. It runs the same way on an EC2 instance, an Azure VM or your own servers: any Linux
host with Docker and a DNS name that points at it.

- **Public API** (port 9090 in the container): pipelines call it through Caddy on 443. It is not
  published directly.
- **Admin API** (port 9091): registering targets and issuing tokens. Published on `127.0.0.1:9091`
  only, so you reach it from a shell on the host (or through an SSH tunnel). Caddy never proxies it.
- **Work volume** (`work`, mounted at `/work`): `control.db`, each target's project file, runs and
  snapshots. Back it up.

## Limits

- **One replica.** The server keeps its state in SQLite and per-target project files on one
  volume. Don't run two copies against the same volume, and don't scale the service.
- **Local volume only.** No NFS, EFS, Azure Files or other network filesystems: SQLite and the
  project files need local disk and working file locks. The server refuses to start on one.
- At most 10 targets per server.

## Setup

Run these in this directory (`deploy/compose`).

1. Point a DNS name at the host and open ports 80 and 443 (80 is needed for the certificate).

2. Create the admin token. The container runs as UID 1000 and must be able to read it:

   ```sh
   mkdir -p secrets
   openssl rand -hex 32 > secrets/admin_token
   sudo chown 1000:1000 secrets/admin_token && chmod 600 secrets/admin_token
   ```

   Keep `secrets/` out of version control.

3. Start it:

   ```sh
   export SCAN_HOSTNAME=scan.corp.test
   docker compose up -d
   docker compose logs -f brainproxy-server   # wait for the listeners
   curl https://$SCAN_HOSTNAME/v1/healthz
   ```

4. Register a target (admin API, from the host). This one has the server generate the project
   with a login profile; the password comes from a secret, never from the registration:

   ```sh
   ADMIN="Authorization: Bearer $(cat secrets/admin_token)"
   curl -sS -H "$ADMIN" -H 'Content-Type: application/json' http://127.0.0.1:9091/v1/targets -d '{
     "id": "shop-dev",
     "base_url": "https://shop-dev.corp.test/",
     "scope": ["shop-dev.corp.test"],
     "preset": "standard",
     "max_minutes": 45,
     "gate": {"fail_on": "high", "new_only": true},
     "auth": {
       "name": "user",
       "login_url": "https://shop-dev.corp.test/login",
       "username": "scanner",
       "password_env": "APP_PASSWORD",
       "check_url": "https://shop-dev.corp.test/me",
       "logged_in": "Sign out"
     },
     "secret_env": {"APP_PASSWORD": "SHOP_DEV_APP_PASSWORD"}
   }'
   ```

   `secret_env` maps the variable the CLI reads (`APP_PASSWORD`) to its source. The server reads
   the file `/run/secrets/shop-dev/APP_PASSWORD` first, and the server's environment variable
   `SHOP_DEV_APP_PASSWORD` if there is no file. With Compose, use a file: uncomment the
   `shop_dev_app_password` example in `docker-compose.yml`, then

   ```sh
   mkdir -p secrets/shop-dev
   printf '%s' 'the-password' > secrets/shop-dev/APP_PASSWORD
   sudo chown 1000:1000 secrets/shop-dev/APP_PASSWORD && chmod 600 secrets/shop-dev/APP_PASSWORD
   docker compose up -d
   ```

   Without a login, leave out `auth` and `secret_env`. To scan with a project prepared in the app
   instead, register with `"project": "upload"` (and `"auth_profile"` for its login profile) and
   upload the file with `PUT /v1/targets/shop-dev/project`.

   For an app with known issues, make the first run a baseline (no gate; later runs count as new
   only what appears after it):

   ```sh
   curl -sS -H "$ADMIN" -H 'Content-Type: application/json' \
     http://127.0.0.1:9091/v1/targets/shop-dev/next-run -d '{"baseline": true}'
   ```

5. Issue a token for the pipeline. It is shown once; store it as a CI secret named
   `BRAINPROXY_TOKEN`:

   ```sh
   curl -sS -H "$ADMIN" -H 'Content-Type: application/json' \
     http://127.0.0.1:9091/v1/targets/shop-dev/tokens -d '{"name": "github-actions"}' | jq -r .data.token
   ```

   Tokens can trigger runs by default (`"perm": "trigger"`); `"perm": "read"` only reads results.
   They expire (`"expires_days"`, 1 to 3650). List them with `GET .../tokens` and revoke one with
   `DELETE .../tokens/<id>`.

6. Call it from the pipeline:

   ```sh
   BRAINPROXY_TOKEN=... brainproxy-server remote run --server https://scan.corp.test \
     --target shop-dev --commit "$GIT_SHA" --ref "$GIT_REF" --pipeline-url "$PIPELINE_URL" \
     --sarif brainproxy.sarif
   ```

   It exits with the run's code: 0 passed, 5 the gate failed, 2 incomplete, superseded, cancelled
   or timed out, 3 server unreachable, 4 unknown target, 6 out of scope, 1 anything else.
   See [`contrib/ci/`](../../contrib/ci/) for GitHub Actions, GitLab CI and Azure Pipelines, and
   [`contrib/remote.sh`](../../contrib/remote.sh) for a `curl` version.

## Notes

- **A dev instance on the Docker host itself:** inside the container, `localhost` is the container.
  Register the host's DNS name or LAN address instead. `host.docker.internal` also works, on Linux
  after adding `extra_hosts: ["host.docker.internal:host-gateway"]` to `brainproxy-server`.
- `--allow-loopback-targets` lets a scope name `localhost` or `127.0.0.1`. It is only for trying the
  server out locally, never for a deployment.
- The server needs outbound access to the targets only. Restrict its egress with the host firewall
  or security group if you can.
- The admin port is also reachable from other containers on the Compose network (such as Caddy),
  though they still need the admin token. Keep other services off this network.
- The root filesystem is read-only; the server writes only under `/work` (and the `/tmp` tmpfs).
- Restarting the container also ends the scans running in it: they are processes in the same
  container. The server picks those runs up again when it starts, but a scan that was cut off
  can't pass. Restart between scans when you can.
- Upgrades: `docker compose build --pull && docker compose up -d`. To change the brainproxy CLI
  version, change the build arguments in `docker/server.Dockerfile`.
