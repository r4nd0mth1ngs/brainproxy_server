# AWS Fargate (ECS) example

One Fargate task behind an Application Load Balancer, with `/work` on the task's ephemeral storage
and its state kept in S3 (`--store`). The files here are examples: replace the account id
`111122223333`, region, ARNs, subnets, security group and bucket.

- `task-definition.json`: the task (`aws ecs register-task-definition --cli-input-json file://task-definition.json`).
- `service.json`: the service (`aws ecs create-service --cli-input-json file://service.json`).
- `task-role-policy.json`: the task role's policy: the bucket prefix and ECS Exec.

## Why object storage

A Fargate task's storage goes away when the task stops, and EFS is a network filesystem, which the
server refuses (SQLite and file locks need local disk). So `/work` is local and temporary, and the
image must be built with object storage:

```sh
docker buildx build --platform linux/amd64 -f docker/server.Dockerfile \
  --build-arg CARGO_FEATURES=object-store \
  -t 111122223333.dkr.ecr.eu-west-1.amazonaws.com/brainproxy-server:TAG --push .
```

With `BRAINPROXY_SERVER_STORE=s3://bucket/prefix`, the server uploads `control.db`, the target's
newest project snapshot and the run's files after each run and after each admin change, and a task
that starts with an empty `/work` restores from the bucket first. Credentials come from the task
role; `AWS_REGION` names the bucket's region. A task replaced in the middle of a scan loses that
scan (the run ends incomplete), as with any restart.

## One task, never two

`desiredCount` is 1 and the deployment allows 0 to 100 percent: ECS stops the old task before it
starts the new one, so two servers never write to the same prefix. A deployment therefore has a
short outage. Don't use auto scaling, and don't point a second service at the same prefix.

## Secrets

Fargate can't mount secrets as files, only as environment variables (`secrets` with
`valueFrom`), so the task uses the server's two other paths:

- **Admin token**: the server reads it from a file, so the container's command writes the
  `ADMIN_TOKEN` variable to `/tmp/admin_token` (mode 600) and removes it from the environment
  before starting the server. Create it with
  `aws secretsmanager create-secret --name brainproxy/admin-token --secret-string "$(openssl rand -hex 32)"`.
- **Target secrets**: with no file under `--secrets-dir`, the server reads the environment
  variable that the target's `secret_env` names. A target registered with
  `"secret_env": {"APP_PASSWORD": "SHOP_DEV_APP_PASSWORD"}` gets its password from the
  `SHOP_DEV_APP_PASSWORD` entry in `secrets`. Each CLI process only gets its own target's secrets.
  Adding a target's secret means a new task definition revision and a deployment.

The execution role needs `secretsmanager:GetSecretValue` on those secrets (and `kms:Decrypt` for
a customer managed key), besides the usual `AmazonECSTaskExecutionRolePolicy`.

## Admin access

The admin API listens on `127.0.0.1:9091` in the task; it has no port mapping and the load balancer
never reaches it. Use ECS Exec (`enableExecuteCommand` in the service, the `ssmmessages` actions in
the task role, and the Session Manager plugin for the AWS CLI):

```sh
TASK=$(aws ecs list-tasks --cluster brainproxy --service-name brainproxy-server --query 'taskArns[0]' --output text)
aws ecs execute-command --cluster brainproxy --task "$TASK" --container brainproxy-server \
  --interactive --command /bin/sh
# in the task (BusyBox wget, no curl):
wget -qO- --header "Authorization: Bearer $(cat /tmp/admin_token)" http://127.0.0.1:9091/v1/summary
```

To use `curl` from your machine, or to upload a project (`PUT .../project`), forward the port
through Session Manager to the same task:

```sh
RUNTIME=$(aws ecs describe-tasks --cluster brainproxy --tasks "$TASK" \
  --query 'tasks[0].containers[?name==`brainproxy-server`].runtimeId | [0]' --output text)
aws ssm start-session --target "ecs:brainproxy_${TASK##*/}_${RUNTIME}" \
  --document-name AWS-StartPortForwardingSession --parameters portNumber=9091,localPortNumber=9091
```

Then register targets and issue tokens as in [`deploy/compose/README.md`](../compose/README.md)
steps 4 to 6, against `http://127.0.0.1:9091`. ECS Exec doesn't work with a read-only root
filesystem, which is why `readonlyRootFilesystem` is false here; the server still writes only to
`/work` and `/tmp`. Give `ecs:ExecuteCommand` and `ssm:StartSession` on this cluster to admins only.

## Network

- **Load balancer**: an HTTPS listener (ACM certificate) forwarding to a target group of type `ip`
  on port 9090, health check `GET /v1/healthz`. Set the load balancer's idle timeout to 120 seconds:
  run status requests long-poll for up to 60. `--trust-forwarded` is set because the load balancer
  adds `X-Forwarded-For`; remove it without one.
- **Security group** of the task: in, port 9090 from the load balancer's security group only. Out,
  the targets' addresses and ports, and 443 to S3 (better: an S3 gateway endpoint and its prefix
  list), plus the OIDC issuers if you use OIDC from CI. Private subnets; the task needs no public IP
  with a NAT gateway or VPC endpoints for ECR, Secrets Manager, CloudWatch Logs and SSM.

## Notes

- Size: 2 vCPU and 8 GiB suit up to three standard scans at once (`--max-parallel`, 3). The 50 GiB
  of ephemeral storage hold `/work`; raise it (up to 200) for large projects or many runs.
- The task definition mounts a volume named `work` at `/work`. Fargate fills it from the image's
  `/work`, which is owned by UID 1000. If the server logs a permission error on `/work`, check the
  platform version (1.4.0 or later).
- `stopTimeout` is 60 seconds: the server stops its listeners within 5 seconds of SIGTERM; the rest
  is room for the last upload.
- `initProcessEnabled` gives ECS Exec an init process; the image's `tini` runs under it with `-s`.
- Upgrades: push a new image tag, register a new task definition revision and update the service.
  Upgrade between scans when you can (`GET /v1/summary`).
