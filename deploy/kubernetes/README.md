# Kubernetes deployment

Plain manifests and a `kustomization.yaml`, in the namespace `brainproxy`:

- **StatefulSet** with one pod and a ReadWriteOnce volume for `/work` (`control.db`, each target's
  project file, runs and snapshots).
- **Service** (ClusterIP, port 9090) for the public API, and an optional **Ingress** for it.
- **Admin API** on `127.0.0.1:9091` inside the pod. No Service, no Ingress: reach it with
  `kubectl port-forward` or `kubectl exec`.
- **NetworkPolicy**: in from the Ingress controller, out to DNS and the targets.

## Limits

- **One replica.** The server keeps its state in SQLite and per-target project files on one
  volume, with file locks. Don't scale the StatefulSet, and don't run a second server against the
  same volume or object store prefix. A StatefulSet deletes its pod before starting the new one,
  so upgrades don't overlap.
- **Block storage only** for `/work` (EBS, Azure Disk, Persistent Disk, local volumes). No NFS,
  EFS, Azure Files or other network filesystems: the server refuses to start on one.
- At most 10 targets per server.

## Setup

1. Build the image from the repository root and push it to your registry. There is no published
   image. Add `--build-arg CARGO_FEATURES=object-store` for object storage (see Backup):

   ```sh
   docker buildx build --platform linux/amd64,linux/arm64 -f docker/server.Dockerfile \
     -t ghcr.io/OWNER/brainproxy-server:TAG --push .
   ```

   Set `OWNER` and `TAG` under `images` in `kustomization.yaml`.

2. Check the placeholders: the Ingress controller's namespace and the targets' addresses in
   `networkpolicy.yaml`, the storage class in `statefulset.yaml`, and, if you use it, the host and
   TLS secret in `ingress.yaml` (then enable it in `kustomization.yaml`). Remove
   `--trust-forwarded` from `statefulset.yaml` if nothing in front of the Service sets
   `X-Forwarded-For`.

3. Create the namespace and the admin token (see Secrets), then apply:

   ```sh
   kubectl apply -f deploy/kubernetes/namespace.yaml
   kubectl -n brainproxy create secret generic brainproxy-admin \
     --from-literal=token="$(openssl rand -hex 32)"
   kubectl apply -k deploy/kubernetes
   kubectl -n brainproxy rollout status statefulset/brainproxy-server
   kubectl -n brainproxy logs brainproxy-server-0    # "API on 0.0.0.0:9090, admin on 127.0.0.1:9091"
   ```

4. Register targets and issue tokens through the admin API (below), as in
   [`deploy/compose/README.md`](../compose/README.md) steps 4 to 6.

## Secrets

- **Admin token**: the Secret `brainproxy-admin`, key `token`, mounted at
  `/run/brainproxy-admin/token` (`--admin-token-file`). At least 32 characters. The server reads it
  at start: restart the pod after changing it.
- **Target secrets**: the server reads `--secrets-dir/<target>/<VARIABLE>`, here
  `/run/secrets/<target>/<VARIABLE>`, for each variable a target's `secret_env` names (README,
  "Secrets"). Use one Secret per target whose keys are the variables, and mount it at
  `/run/secrets/<target>`. `statefulset.yaml` has one for the target `shop-dev`:

  ```sh
  kubectl -n brainproxy create secret generic brainproxy-target-shop-dev \
    --from-literal=APP_PASSWORD='the-password'
  ```

  For another target, add a volume and a mount like `target-shop-dev`. Values are read for each
  run, so a changed Secret is picked up without a restart once the kubelet has synced it
  (about a minute).

Don't keep Secret manifests with values in version control; use `kubectl create secret`, or a
secret manager through the External Secrets Operator or the Secrets Store CSI driver, which produce
the same Secrets.

## Admin access

The admin API is on loopback in the pod. Either forward it to your machine:

```sh
kubectl -n brainproxy port-forward pod/brainproxy-server-0 9091:9091 &
ADMIN="Authorization: Bearer $(kubectl -n brainproxy get secret brainproxy-admin -o jsonpath='{.data.token}' | base64 -d)"
curl -sS -H "$ADMIN" http://127.0.0.1:9091/v1/summary
curl -sS -H "$ADMIN" -T app.bpdb http://127.0.0.1:9091/v1/targets/shop-dev/project
```

or run a request inside the pod (the image has BusyBox `wget`, not `curl`):

```sh
kubectl -n brainproxy exec brainproxy-server-0 -- sh -c \
  'wget -qO- --header "Authorization: Bearer $(cat /run/brainproxy-admin/token)" http://127.0.0.1:9091/v1/summary'
```

Both need `pods/portforward` or `pods/exec` in the namespace: give those RBAC rights only to admins.

## Upgrade

Change the tag in `kustomization.yaml` and `kubectl apply -k deploy/kubernetes`. The pod is
replaced, which ends the scans running in it (those runs end incomplete). Check
`GET /v1/summary` and upgrade between scans when you can. To change the brainproxy CLI version,
change the build arguments in `docker/server.Dockerfile` and build a new image.

## Backup

The volume holds everything. Either:

- **Object storage** (image built with `CARGO_FEATURES=object-store`): set `BRAINPROXY_SERVER_STORE`
  in `statefulset.yaml` to `s3://bucket/prefix` or `az://container/prefix`, with credentials from
  the standard environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, or
  `AZURE_STORAGE_ACCOUNT_NAME` and `AZURE_STORAGE_ACCOUNT_KEY`) from a Secret, or from workload
  identity (see `serviceaccount.yaml`). MinIO works through `s3://` with `AWS_ENDPOINT` and, over
  plain HTTP, `AWS_ALLOW_HTTP=true`. After each run and each admin change the server uploads
  `control.db`, the target's newest project snapshot and the run's files. A pod that starts with an
  empty volume restores from the store first, so a lost volume only costs what happened since the
  last upload. Open egress to the store (`networkpolicy.yaml`).
- **Volume snapshots** (`VolumeSnapshot` with your CSI driver), taken between scans.

## Notes

- Probes call `GET /v1/healthz` on the public port. The startup probe allows 10 minutes for a
  restore from the object store. Most CNIs let the kubelet's probes through a NetworkPolicy; if
  yours doesn't, allow the nodes' addresses to port 9090.
- The pod runs as UID 1000 with a read-only root filesystem, no capabilities, the `RuntimeDefault`
  seccomp profile and no service account token, and meets the `restricted` Pod Security Standard.
  It writes only to `/work` and `/tmp` (an `emptyDir`).
- Resources: scans run as CLI processes inside the pod, up to `--max-parallel` (3) at once. The
  defaults (1 CPU and 2 GiB requested, 4 CPU and 6 GiB limit) suit a few standard scans; give it
  more memory for thorough presets or a higher `--max-parallel`.
- NetworkPolicy only works with a CNI that enforces it. Restrict egress to the targets'
  addresses: the server checks scope itself, but the firewall is the layer that holds if a target
  name is re-pointed.
- With one replica, a PodDisruptionBudget would block node drains; there is none. Drains restart the
  pod like an upgrade does.
- The Ingress raises the read timeout to 120 seconds for the 60-second long polls. Other
  controllers need the same.
