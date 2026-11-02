# Azure Container Apps example

One replica of brainproxy-server with `/work` on replica storage and its state in Azure Blob
Storage (`--store`). `containerapp.yaml` is an example for
`az containerapp create --yaml`: replace `SUB`, `RG`, the registry, vault, storage account,
identity and client id.

## Why object storage

Replica storage (`EmptyDir`) goes away with the replica, and Azure Files is SMB, a network
filesystem, which the server refuses (SQLite and file locks need local disk). So `/work` is local
and temporary, and the image must be built with object storage:

```sh
docker buildx build --platform linux/amd64 -f docker/server.Dockerfile \
  --build-arg CARGO_FEATURES=object-store -t myregistry.azurecr.io/brainproxy-server:TAG --push .
```

With `BRAINPROXY_SERVER_STORE=az://container/prefix` (`azure://` works too), the server uploads
`control.db`, the target's newest project snapshot and the run's files after each run and after
each admin change, and a replica that starts with an empty `/work` restores from the container
first. Credentials: `AZURE_STORAGE_ACCOUNT_NAME` plus the managed identity (`AZURE_CLIENT_ID` picks
the user-assigned one; give it Storage Blob Data Contributor on the container), or
`AZURE_STORAGE_ACCOUNT_KEY` from a secret instead of the identity. A replica replaced in the middle
of a scan loses that scan (the run ends incomplete), as with any restart.

## Setup

```sh
az identity create -g RG -n brainproxy-server
az storage container create --account-name mybrainproxystorage -n brainproxy --auth-mode login
az keyvault secret set --vault-name my-vault -n brainproxy-admin-token --value "$(openssl rand -hex 32)"
az keyvault secret set --vault-name my-vault -n brainproxy-shop-dev-app-password --value 'the-password'
# Roles for the identity: AcrPull on the registry, Key Vault Secrets User on the vault,
# Storage Blob Data Contributor on the storage container.
az containerapp create -g RG -n brainproxy-server --yaml deploy/azure-container-apps/containerapp.yaml
curl https://$(az containerapp show -g RG -n brainproxy-server --query properties.configuration.ingress.fqdn -o tsv)/v1/healthz
```

## One replica, never two

`minReplicas` and `maxReplicas` are 1. Container Apps still starts a new revision before it stops
the old one when you change the app, so for a short time two servers run against the same
container. To upgrade without that overlap, deactivate the running revision first (this stops the
server; wait until no run is running, `GET /v1/summary`), then update:

```sh
az containerapp revision deactivate -g RG -n brainproxy-server \
  --revision "$(az containerapp show -g RG -n brainproxy-server --query properties.latestRevisionName -o tsv)"
az containerapp update -g RG -n brainproxy-server --image myregistry.azurecr.io/brainproxy-server:NEWTAG
```

Never point a second app at the same container and prefix.

## Secrets

- **Admin token**: a Key Vault secret, mounted as the file `/run/brainproxy-admin/token` through a
  `Secret` volume (`--admin-token-file`). The server reads it at start: restart the app after
  changing it.
- **Target secrets**: environment variables with `secretRef`. With no file under `--secrets-dir`,
  the server reads the variable a target's `secret_env` names: a target registered with
  `"secret_env": {"APP_PASSWORD": "SHOP_DEV_APP_PASSWORD"}` gets `SHOP_DEV_APP_PASSWORD`. Each CLI
  process only gets its own target's secrets. A new target's secret means a new revision (see
  above for the overlap).

## Admin access

The admin API listens on `127.0.0.1:9091` in the replica and ingress never reaches it. Open a shell
in the replica:

```sh
az containerapp exec -g RG -n brainproxy-server --command sh
# in the replica (BusyBox wget, no curl):
ADMIN="Authorization: Bearer $(cat /run/brainproxy-admin/token)"
wget -qO- --header "$ADMIN" http://127.0.0.1:9091/v1/summary
wget -qO- --header "$ADMIN" --header 'Content-Type: application/json' \
  --post-data '{"name": "github-actions"}' http://127.0.0.1:9091/v1/targets/shop-dev/tokens
```

Register targets and issue tokens as in [`deploy/compose/README.md`](../compose/README.md) steps 4
to 6. Container Apps has no port forwarding, so uploading a project file (`PUT .../project`) isn't
practical here: register targets with a generated project and a login profile. Give the
`Microsoft.App/containerApps/exec/action` permission to admins only.

## Network

- Ingress terminates TLS; `--trust-forwarded` is set because it adds `X-Forwarded-For`. Its request
  timeout (240 seconds) covers the 60-second long polls. `ipSecurityRestrictions` can limit the
  public API to your CI runners' addresses.
- Restricting egress to the targets' addresses needs an environment in your own virtual network,
  with a network security group or Azure Firewall on its subnet. Allow the targets, the storage
  account (a private endpoint is better), Key Vault, the registry and the OIDC issuers if you use
  OIDC from CI.

## Notes

- Size: 2 vCPU and 4 GiB suit a couple of standard scans at once. On the Consumption plan, replica
  storage is limited (a few GiB, depending on the CPU); for large projects or `--max-parallel` 3
  use a dedicated workload profile.
- `terminationGracePeriodSeconds` is 60: the server stops its listeners within 5 seconds of
  SIGTERM; the rest is room for the last upload.
- The startup probe allows 5 minutes for a restore from the store.
