# SecureOps Platform

> An event-driven microservice platform built on **Dapr**, deployed to **Kubernetes** with **Terraform / Ansible**, and protected by a **DevSecOps CI/CD pipeline** (GitHub Actions) that gates every push on SAST, secret scanning, dependency auditing, IaC and container image scanning, SBOM generation, image signing and dynamic testing (OWASP ZAP). Findings land in the **GitHub Security tab** and trigger **chat webhook alerts**.

![status](https://img.shields.io/badge/status-prototype-orange)
![pipeline](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF)
![runtime](https://img.shields.io/badge/runtime-Dapr%20%2B%20Kubernetes-326CE5)
![license](https://img.shields.io/badge/license-MIT-green)

> Replace `<your-user>/secureops-platform` in badge and clone URLs with your own repository path.

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Goals and non-goals](#2-goals-and-non-goals)
3. [Architecture](#3-architecture)
4. [The application (microservices)](#4-the-application-microservices)
5. [Dapr building blocks](#5-dapr-building-blocks)
6. [Infrastructure as Code](#6-infrastructure-as-code)
7. [CI/CD pipeline (DevSecOps)](#7-cicd-pipeline-devsecops)
8. [Security gates and severity policy](#8-security-gates-and-severity-policy)
9. [Findings management and alerting](#9-findings-management-and-alerting)
10. [Runtime and cluster security](#10-runtime-and-cluster-security)
11. [Observability](#11-observability)
12. [Threat model (STRIDE)](#12-threat-model-stride)
13. [Repository layout](#13-repository-layout)
14. [Prerequisites and hardware](#14-prerequisites-and-hardware)
15. [Quick start](#15-quick-start)
16. [Demo scenarios](#16-demo-scenarios)
17. [Configuration and secrets](#17-configuration-and-secrets)
18. [Testing strategy](#18-testing-strategy)
19. [Roadmap and stretch goals](#19-roadmap-and-stretch-goals)
20. [Known limitations](#20-known-limitations)
21. [Tool reference](#21-tool-reference)
22. [License](#22-license)

---

## 1. Project overview

**SecureOps Platform** is an academic DevOps project that doubles as a portfolio-grade DevSecOps reference implementation. It has two layers:

| Layer | What it is | Why it matters |
|---|---|---|
| **Platform** | A small order-processing system made of Python/FastAPI microservices that communicate through **Dapr** (service invocation, pub/sub, state, secrets, bindings), running on **Kubernetes**. | Demonstrates cloud-native architecture, service-to-service security (mTLS) and resilient messaging. |
| **Delivery pipeline** | A **GitHub Actions** workflow that refuses to ship code unless it passes secret scanning, SAST, dependency audit, IaC/container scanning and DAST, and that produces a signed image plus an **SBOM** for every build. | Demonstrates shift-left security, supply-chain integrity and automated, auditable releases. |

The application is deliberately simple so the **pipeline, infrastructure code and security controls** are the focus.

### The core idea

```
 code push ──► gates (secrets, SAST, deps, IaC, image) ──► SBOM + signature
                                                              │
                                                              ▼
        chat alert ◄── findings ◄── ZAP DAST ◄── ephemeral Kubernetes deploy
```

Nothing reaches the cluster unless it passes the gates, and the cluster itself only admits images that were signed by this pipeline.

---

## 2. Goals and non-goals

**Goals**

- Build a Dapr-based microservice platform and deploy it on Kubernetes with Helm.
- Provision everything reproducibly with **Terraform** (cluster, namespaces, Dapr, policies) and **Ansible** (host bootstrap and hardening).
- Implement a **gating** DevSecOps pipeline with: Gitleaks, Semgrep, pip-audit, Hadolint, Trivy (config and image), Syft (SBOM), Cosign (signing and attestation), OWASP ZAP.
- Centralize findings in the **GitHub Security tab** (SARIF) and notify a **chat channel** through a webhook.
- Enforce supply-chain and runtime policies in the cluster (Kyverno, NetworkPolicies, Pod Security Standards).
- Everything is runnable from the **terminal**, on a single laptop, with **no cloud account required**.

**Non-goals**

- Production-grade business logic (payments are mocked).
- A full SOC stack (Wazuh, Shuffle and similar were intentionally dropped to keep the project lightweight; see [Roadmap](#19-roadmap-and-stretch-goals)).
- Multi-region or high-availability cluster design.

---

## 3. Architecture

### 3.1 High-level view

```
                       ┌─────────────────────────── GitHub ───────────────────────────┐
                       │  Repo ─► Actions pipeline ─► GHCR (signed images + SBOM)     │
                       │                    │                                         │
                       │                    └─► Security tab (SARIF)  ─► chat webhook │
                       └──────────────────────────────────────────────────────────────┘
                                                   │ images
                                                   ▼
┌────────────────────────────── Kubernetes (kind / k3s) ──────────────────────────────┐
│  Kyverno (admission: signed images only, no privileged pods)                        │
│  NetworkPolicies (default deny)   Pod Security Standards (restricted)               │
│                                                                                     │
│  namespace: secureops                                                               │
│  ┌──────────────┐  invoke   ┌───────────────┐  invoke   ┌─────────────────┐         │
│  │ api-gateway  │ ────────► │ order-service │ ────────► │ payment-service │         │
│  │ (JWT auth)   │           │               │           │ (mock)          │         │
│  └──────────────┘           └──────┬────────┘           └─────────────────┘         │
│     + Dapr sidecar                 │ publish: order-created                          │
│                                    ▼                                                 │
│                            ┌───────────────┐   publish: order-confirmed              │
│                            │ pub/sub broker│ ◄───────────────────────┐               │
│                            └──────┬────────┘                         │               │
│                                   │ subscribe                        │               │
│                           ┌───────▼─────────┐                ┌───────┴────────────┐  │
│                           │inventory-service│                │notification-service│  │
│                           └───────┬─────────┘                └───────┬────────────┘  │
│                                   │                                  │ output binding│
│                            ┌──────▼───────┐                          ▼ (HTTP)        │
│                            │ state store  │                    chat webhook / mail   │
│                            └──────────────┘                                          │
│                                                                                     │
│  Every pod has a Dapr sidecar; sidecar-to-sidecar traffic is mTLS (Dapr Sentry)     │
│                                                                                     │
│  namespace: monitoring   Prometheus · Grafana · (optional) Loki / Falco             │
│  namespace: dapr-system  Dapr control plane (operator, placement, sentry, injector) │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Request flow (happy path)

1. A client calls `POST /orders` on **api-gateway** with a JWT.
2. The gateway validates the token and uses **Dapr service invocation** to call **order-service**.
3. order-service saves the order in the **state store** with status `PENDING`, then calls **payment-service** through Dapr service invocation (with retries and a circuit breaker from the resiliency policy).
4. On success, order-service publishes `order-created` on the **pub/sub** topic.
5. **inventory-service** consumes `order-created`, reserves stock in the state store and publishes `order-confirmed` (or `order-rejected`).
6. **notification-service** consumes the result and sends a message through a Dapr **output binding** (HTTP, targeting a webhook).

### 3.3 Environments

| Environment | Where | Purpose |
|---|---|---|
| `ci` | Ephemeral kind cluster inside the GitHub Actions runner | Deploy the build under test and run ZAP against it, then throw it away. |
| `dev` | Local kind/k3s cluster on your machine | Day-to-day development and demos. |
| `staging` (optional) | Second namespace or cluster | Enforce Kyverno signature verification in `Enforce` mode. |

---

## 4. The application (microservices)

All services are Python 3.12 + FastAPI, packaged as non-root container images, each with `/healthz` and `/readyz` endpoints.

| Service | Responsibility | Talks to | Dapr features used |
|---|---|---|---|
| **api-gateway** | Public entry point, JWT validation, input validation, rate limiting | order-service | Service invocation, secrets (JWT key) |
| **order-service** | Creates and tracks orders | payment-service, pub/sub, state store | Service invocation, state, pub/sub, resiliency |
| **inventory-service** | Reserves stock for confirmed orders | pub/sub, state store | Pub/sub subscribe, state |
| **payment-service** (mock) | Simulates payment authorization (configurable failure rate) | none | Service invocation (callee) |
| **notification-service** | Sends outcome notifications | pub/sub, webhook | Pub/sub subscribe, output binding |

### API surface (gateway)

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/token` | Issues a short-lived JWT (demo users only) |
| `POST` | `/orders` | Create an order |
| `GET` | `/orders/{id}` | Get order status |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |
| `GET` | `/openapi.json` | OpenAPI spec (consumed by ZAP in the pipeline) |

### Container hardening conventions

- Multi-stage Dockerfiles, slim or distroless base images, pinned versions.
- Run as non-root, read-only root filesystem, all Linux capabilities dropped.
- No secrets baked into images; configuration through env vars and the Dapr secret store.

---

## 5. Dapr building blocks

| Building block | Component | Used for |
|---|---|---|
| **Service invocation** | built-in | Service-to-service calls with discovery, retries and mTLS |
| **Pub/Sub** | `pubsub` (Redis Streams or RabbitMQ) | Asynchronous order events |
| **State management** | `statestore` (Redis) | Orders and stock levels |
| **Secrets** | `secretstore` (Kubernetes secrets; Vault as a stretch goal) | JWT signing key, webhook URL |
| **Bindings (output)** | `notify-webhook` (HTTP) | Outbound chat/webhook notifications |
| **Resiliency** | `resiliency.yaml` | Timeouts, retries with backoff, circuit breakers |
| **Configuration / access control** | `config.yaml` | Allow-list of which app-ids may call which services; tracing config |

Example access-control policy (only the gateway may call order-service):

```yaml
apiVersion: dapr.io/v1alpha1
kind: Configuration
metadata:
  name: order-service-config
spec:
  accessControl:
    defaultAction: deny
    trustDomain: "secureops"
    policies:
      - appId: api-gateway
        defaultAction: allow
        trustDomain: "secureops"
        namespace: "secureops"
```

---

## 6. Infrastructure as Code

### 6.1 Terraform

Terraform provisions the cluster and everything that must exist before an application is deployed.

| Module | Provider(s) | Creates |
|---|---|---|
| `modules/cluster` | `tehcyx/kind` | A kind cluster (1 control-plane + 2 workers), port mappings for ingress/testing |
| `modules/dapr` | `helm` | Dapr control plane (with mTLS enabled) |
| `modules/platform` | `kubernetes` | Namespaces, ResourceQuotas, LimitRanges, default-deny NetworkPolicies, Pod Security labels, RBAC |
| `modules/security` | `helm`, `kubernetes` | Kyverno and the cluster policies (signed images only, no privileged containers, resource limits required) |
| `modules/observability` | `helm` | kube-prometheus-stack (Prometheus + Grafana), optional Loki |

IaC is itself scanned in the pipeline (`terraform fmt -check`, `terraform validate`, `trivy config`).

### 6.2 Ansible

Ansible covers the machine the cluster runs on (your laptop, a VM or a small VPS):

- Installs Docker, kubectl, kind, Helm, Terraform and the scanning CLIs.
- Applies baseline hardening (non-root user, SSH hardening, firewall rules, automatic security updates).
- Is idempotent: re-running it should change nothing.

### 6.3 Helm

Each service has a Helm chart (or a shared chart with per-service values) with: Deployment with Dapr annotations, Service, ServiceAccount, securityContext defaults, probes, resource requests/limits, and an optional HorizontalPodAutoscaler.

---

## 7. CI/CD pipeline (DevSecOps)

The pipeline lives in `.github/workflows/devsecops.yml` and runs on every push and pull request. A pipeline run is a graph of jobs; a failed **gate** blocks the merge and everything downstream.

```
                         ┌──────────────┐
                         │ 1. secrets   │  Gitleaks
                         ├──────────────┤
                         │ 2. sast      │  Semgrep
 push / PR ─────────────►├──────────────┤
                         │ 3. deps      │  pip-audit
                         ├──────────────┤
                         │ 4. iac-lint  │  Hadolint · terraform validate · Trivy config
                         └──────┬───────┘
                                │ (all gates green)
                         ┌──────▼───────┐
                         │ 5. build     │  Docker build (matrix: 5 services)
                         │    scan      │  Trivy image scan (gate)
                         │    sbom      │  Syft → CycloneDX SBOM
                         └──────┬───────┘
                                │
                         ┌──────▼───────┐
                         │ 6. deploy +  │  Ephemeral kind cluster (Terraform + Helm)
                         │    DAST      │  OWASP ZAP API scan against the gateway
                         └──────┬───────┘
                                │
                         ┌──────▼───────┐   (main branch only)
                         │ 7. publish   │  Push to GHCR · Cosign sign · attest SBOM
                         └──────┬───────┘
                                │
                         ┌──────▼───────┐   (always)
                         │ 8. notify    │  Summary → chat webhook
                         └──────────────┘
```

### 7.1 Stage details

| # | Stage | Tool | What it checks | Output |
|---|---|---|---|---|
| 1 | Secret scanning | **Gitleaks** | Hard-coded credentials, API keys and tokens in the working tree and git history | SARIF to Security tab |
| 2 | SAST | **Semgrep** | Insecure code patterns (injection, unsafe deserialization, weak crypto, etc.) using the `p/ci`, `p/python` and `p/owasp-top-ten` rulesets | SARIF to Security tab |
| 3 | Dependency audit | **pip-audit** | Known vulnerabilities (CVEs) in Python dependencies | JSON artifact and job summary |
| 4a | Dockerfile lint | **Hadolint** | Dockerfile best practices and risky instructions | SARIF |
| 4b | IaC checks | **terraform validate**, **Trivy config** | Misconfigurations in Terraform, Kubernetes manifests and Helm output | SARIF |
| 5a | Image scan | **Trivy** | OS and library vulnerabilities in each built image | SARIF to Security tab |
| 5b | SBOM | **Syft** | Full software bill of materials, CycloneDX JSON, one per image per build | Build artifact (and attestation on `main`) |
| 6 | DAST | **OWASP ZAP** | Runtime vulnerabilities in the deployed API (driven by the OpenAPI spec) | HTML/JSON report, converted to SARIF |
| 7 | Sign and attest | **Cosign** (keyless, GitHub OIDC) | Image provenance and integrity; SBOM attached as an in-toto attestation | Signature stored next to the image in GHCR |
| 8 | Notify | `curl` to webhook | Pipeline status and severity counts | Chat message |

### 7.2 Key commands used by the pipeline

```bash
# 1. Secrets
gitleaks detect --source . --report-format sarif --report-path gitleaks.sarif

# 2. SAST
semgrep scan --config p/ci --config p/python --config p/owasp-top-ten \
  --sarif --output semgrep.sarif --error

# 3. Dependencies
pip-audit -r services/<svc>/requirements.txt --strict -f json -o pip-audit-<svc>.json

# 4. IaC and Dockerfiles
hadolint services/<svc>/Dockerfile
terraform -chdir=infra/terraform validate
trivy config --format sarif --output trivy-config.sarif --exit-code 1 --severity HIGH,CRITICAL .

# 5. Image scan and SBOM
docker build -t ghcr.io/<your-user>/<svc>:${GITHUB_SHA} services/<svc>
trivy image --format sarif --output trivy-<svc>.sarif \
  --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed ghcr.io/<your-user>/<svc>:${GITHUB_SHA}
syft ghcr.io/<your-user>/<svc>:${GITHUB_SHA} -o cyclonedx-json=sbom-<svc>.cdx.json

# 6. DAST (gateway exposed on localhost:8080 through port-forward)
docker run --rm --network host -v "$PWD:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-api-scan.py -t http://localhost:8080/openapi.json -f openapi -J zap.json -r zap.html

# 7. Sign and attest (main branch)
cosign sign --yes ghcr.io/<your-user>/<svc>@<digest>
cosign attest --yes --type cyclonedx --predicate sbom-<svc>.cdx.json ghcr.io/<your-user>/<svc>@<digest>
```

Results that are natively SARIF are uploaded with `github/codeql-action/upload-sarif`. ZAP's JSON report is converted to SARIF by `scripts/zap2sarif.py`; pip-audit output is kept as an artifact and summarized in the job summary.

### 7.3 Pipeline design principles

- **Fail fast, cheap first:** fast static checks run before image builds and cluster tests.
- **Least privilege:** the workflow declares minimal `permissions:` per job (`security-events: write` only where SARIF is uploaded, `id-token: write` only for signing).
- **Pinned actions:** third-party actions are pinned to a commit SHA, and Dependabot keeps them up to date.
- **No long-lived secrets:** signing uses keyless OIDC; the only secret is the webhook URL.
- **Reproducible and ephemeral:** the DAST target is created and destroyed in each run.

---

## 8. Security gates and severity policy

| Check | Blocks the build when | Otherwise |
|---|---|---|
| Gitleaks | Any secret detected (excluding allow-listed fixtures in `.gitleaks.toml`) | n/a |
| Semgrep | Any finding with severity `ERROR` | `WARNING` / `INFO` reported only |
| pip-audit | Any vulnerability with an available fix | Unfixed issues reported only |
| Hadolint | Rules of level `error` | Lower levels reported only |
| Trivy config | `HIGH` or `CRITICAL` misconfiguration | Lower levels reported only |
| Trivy image | `HIGH` or `CRITICAL` with a fix available (`--ignore-unfixed`) | Others reported only |
| ZAP | Any `High` alert | `Medium` and below reported only |
| Kyverno (cluster) | Unsigned image or privileged pod (in `Enforce` mode) | `Audit` mode in `ci` |

Exceptions are tracked explicitly (`.trivyignore`, `.semgrepignore`, `.gitleaks.toml`), each with a comment stating the reason and an expiry date.

---

## 9. Findings management and alerting

### 9.1 GitHub Security tab (central dashboard)

SARIF reports from Gitleaks, Semgrep, Hadolint, Trivy and ZAP are uploaded with distinct categories, so every finding appears under **Security → Code scanning** with file, line, severity and remediation hints. Pull requests show findings inline.

> **Note:** Code scanning is free for public repositories. For private repositories it requires GitHub Advanced Security. If unavailable, the SARIF files are still stored as workflow artifacts.

### 9.2 Chat webhook alerts

The final job (`notify`) runs even when earlier jobs fail and posts a summary to a Discord, Slack or Telegram webhook (`ALERT_WEBHOOK_URL` secret):

```
🔴 SecureOps pipeline FAILED  ·  main  ·  a1b2c3d
Secrets: 0 · SAST: 2 (1 error) · Deps: 3 · Image: 5 HIGH, 1 CRITICAL · ZAP: 1 High
Run: https://github.com/<your-user>/secureops-platform/actions/runs/<id>
```

The script `scripts/notify.sh` builds the message from the job results and the severity counts extracted from the SARIF/JSON reports. At runtime, **notification-service** can use the same channel through a Dapr output binding, which doubles as a Dapr bindings demo.

---

## 10. Runtime and cluster security

| Control | Implementation | Effect |
|---|---|---|
| **Signed images only** | Kyverno `verifyImages` policy checking Cosign keyless signatures from this repository's workflow identity | Unsigned or foreign images are rejected |
| **No privileged workloads** | Kyverno and Pod Security Standards (`restricted`) | Blocks privileged pods, hostPath, root users |
| **Resource governance** | ResourceQuota, LimitRange, mandatory requests/limits | Limits noisy-neighbour and DoS impact |
| **Network segmentation** | Default-deny NetworkPolicies plus explicit allow rules per service | Limits lateral movement |
| **Service identity and mTLS** | Dapr Sentry (SPIFFE identities) and Dapr access-control policies | Only allowed services can call each other, traffic is encrypted |
| **Secrets handling** | Dapr secret store, no secrets in env vars or images | Reduces leak surface |
| **Least-privilege RBAC** | Dedicated ServiceAccounts, no default token automount where not needed | Reduces blast radius |

Optional runtime detection: **Falco** with **Falcosidekick** can forward suspicious runtime events (shell in container, unexpected outbound connection) to the same chat webhook. See the roadmap.

---

## 11. Observability

- **Metrics:** Prometheus scrapes Dapr, the services and Kubernetes; Grafana ships dashboards for service latency, error rate, pub/sub lag and resource use.
- **Tracing:** Dapr tracing exported to Zipkin or an OpenTelemetry collector, so one order can be followed across all services.
- **Logs:** structured JSON logs with a correlation ID; optional Loki for aggregation.
- **Pipeline metrics (stretch):** build duration, gate failure rate and mean time to remediate (DORA-style) tracked from workflow run data.

---

## 12. Threat model (STRIDE)

| Category | Threat | Mitigation |
|---|---|---|
| **S**poofing | Fake service calls another service | Dapr mTLS with SPIFFE identities; access-control policies |
| **S**poofing | Forged or stolen client token | Short-lived JWTs, signature and expiry validation at the gateway |
| **T**ampering | Modified container image or dependency (supply chain) | SBOM, Trivy and pip-audit, Cosign signatures, Kyverno signature verification |
| **T**ampering | Malicious change to pipeline or IaC | Branch protection, required reviews, pinned actions, IaC scanning |
| **R**epudiation | No trace of who did what | Structured logs with correlation IDs, Kubernetes audit logs, signed provenance |
| **I**nformation disclosure | Secrets in code or images | Gitleaks, Dapr secret store, no secrets in images |
| **I**nformation disclosure | Verbose errors leak internals | Generic error responses, ZAP checks |
| **D**enial of service | Request flood or resource exhaustion | Gateway rate limiting, resource limits and quotas, Dapr circuit breakers |
| **E**levation of privilege | Container breakout or over-privileged pod | Non-root, read-only FS, dropped capabilities, PSS `restricted`, Kyverno policies |

---

## 13. Repository layout

```
secureops-platform/
├── README.md
├── .github/
│   ├── workflows/
│   │   └── devsecops.yml          # the pipeline
│   └── dependabot.yml             # actions + pip + docker updates
├── services/
│   ├── api-gateway/
│   │   ├── app/                   # FastAPI code
│   │   ├── tests/
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── order-service/
│   ├── inventory-service/
│   ├── payment-service/
│   └── notification-service/
├── deploy/
│   ├── helm/                      # charts and values per environment
│   └── dapr/                      # components, resiliency, configuration
│       ├── pubsub.yaml
│       ├── statestore.yaml
│       ├── secretstore.yaml
│       ├── binding-notify.yaml
│       ├── resiliency.yaml
│       └── config.yaml
├── infra/
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── modules/{cluster,dapr,platform,security,observability}/
│   └── ansible/
│       ├── inventory.ini
│       ├── bootstrap.yml
│       └── roles/{tools,hardening}/
├── policies/
│   └── kyverno/                   # verify-images, disallow-privileged, require-limits
├── scripts/
│   ├── notify.sh                  # webhook summary
│   ├── zap2sarif.py               # ZAP JSON → SARIF
│   └── demo-vuln-commit.sh        # injects a known vulnerability for the demo
├── docs/
│   ├── architecture.png
│   ├── threat-model.md
│   └── screenshots/
├── .gitleaks.toml
├── .trivyignore
├── .semgrepignore
├── Makefile                       # make up / down / scan / demo
└── LICENSE
```

---

## 14. Prerequisites and hardware

### Hardware

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 8 GB (tight) | 16 GB |
| CPU | 4 cores | 4+ cores |
| Disk | 30 GB free | 40 GB free |
| Virtualization | **Not required**: kind runs in Docker | n/a |

### Software

Docker, kubectl, kind (or k3s), Helm, Terraform (>= 1.6), Ansible, Python 3.12, and for local runs of the checks: Gitleaks, Semgrep, pip-audit, Hadolint, Trivy, Syft, Cosign, Dapr CLI. The Ansible playbook in `infra/ansible/` installs all of these.

The whole project can be driven **from the terminal**; the only GUIs are optional (GitHub Security tab, Grafana).

---

## 15. Quick start

```bash
# 1. Clone
git clone https://github.com/<your-user>/secureops-platform.git
cd secureops-platform

# 2. (Optional) bootstrap tooling on a fresh machine
ansible-playbook -i infra/ansible/inventory.ini infra/ansible/bootstrap.yml

# 3. Create the cluster and platform components with Terraform
cd infra/terraform
terraform init
terraform apply          # kind cluster, Dapr, Kyverno, monitoring, namespaces, policies
cd ../..

# 4. Apply Dapr components
kubectl apply -f deploy/dapr/ -n secureops

# 5. Build and load images (local dev)
make build               # builds all services
make load                # kind load docker-image ...

# 6. Deploy the services
helm upgrade --install secureops deploy/helm/secureops -n secureops

# 7. Try it
kubectl -n secureops port-forward svc/api-gateway 8080:80 &
TOKEN=$(curl -s -X POST localhost:8080/auth/token -d '{"user":"demo","password":"demo"}' \
  -H 'Content-Type: application/json' | jq -r .access_token)
curl -s -X POST localhost:8080/orders -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"item":"widget","qty":2}'

# 8. Run the security checks locally
make scan                # gitleaks + semgrep + pip-audit + hadolint + trivy

# 9. Tear down
cd infra/terraform && terraform destroy
```

### Enabling the pipeline

1. Push the repository to GitHub.
2. Add the repository secret `ALERT_WEBHOOK_URL` (Discord, Slack or Telegram webhook).
3. Enable **Code scanning** (Settings → Code security).
4. Enable branch protection on `main` and require the pipeline checks to pass.

---

## 16. Demo scenarios

These show the pipeline doing its job and make strong material for a presentation or report.

| # | Scenario | How to trigger | Expected result |
|---|---|---|---|
| 1 | **Secret leak** | Commit a fake AWS key in `app/config.py` | Gitleaks fails the build, alert posted to chat, finding in Security tab |
| 2 | **Vulnerable code** | Add an SQL query built with string concatenation or `eval()` on user input | Semgrep error blocks the merge |
| 3 | **Vulnerable dependency** | Pin an old, vulnerable version of a library in `requirements.txt` | pip-audit and Trivy flag CVEs, build blocked |
| 4 | **Insecure container** | Change Dockerfile to run as root with `latest` base image | Hadolint and Trivy config findings |
| 5 | **Runtime vulnerability** | Remove input validation or add a missing security header on the gateway | ZAP reports a finding against the live deployment |
| 6 | **Supply-chain enforcement** | Try to deploy an unsigned image to the cluster | Kyverno rejects the pod |
| 7 | **Clean run** | Revert all of the above | Green pipeline, signed image, SBOM attached |

`scripts/demo-vuln-commit.sh <scenario-number>` automates injecting each scenario on a throwaway branch. Keep before/after screenshots of each in `docs/screenshots/`.

---

## 17. Configuration and secrets

| Name | Where | Purpose |
|---|---|---|
| `ALERT_WEBHOOK_URL` | GitHub Actions secret | Pipeline notification webhook |
| `jwt-signing-key` | Kubernetes Secret, read through the Dapr secret store | Gateway token signing |
| `notify-webhook-url` | Kubernetes Secret, read through the Dapr secret store | Runtime notification binding |
| `GITHUB_TOKEN` | Provided by Actions | GHCR push and SARIF upload |
| OIDC token | Provided by Actions (`id-token: write`) | Keyless Cosign signing |

**Rules:** no secret ever lives in the repository, Terraform state is not committed (`.gitignore`), and any secret found by Gitleaks must be rotated, not just removed.

---

## 18. Testing strategy

| Level | Tooling | Scope |
|---|---|---|
| Unit | `pytest` | Business logic of each service |
| Contract/API | `pytest` + `httpx`, OpenAPI validation | Gateway endpoints and schemas |
| Integration | `dapr run` locally or in the ephemeral cluster | Pub/sub and state flows between services |
| Security (static) | Gitleaks, Semgrep, pip-audit, Hadolint, Trivy | Every push |
| Security (dynamic) | OWASP ZAP | Every pipeline run on the ephemeral deployment |
| Policy | `kyverno test`, `terraform validate` | Cluster policies and IaC |

---

## 19. Roadmap and stretch goals

- [ ] **Argo CD** for GitOps-style deployment
- [ ] **Falco + Falcosidekick** for runtime detection, forwarding to the chat webhook
- [ ] **HashiCorp Vault** as Dapr secret store
- [ ] **SLSA provenance** attestation (`slsa-github-generator`)
- [ ] **Dependency-Track** to ingest SBOMs and track component risk over time
- [ ] **DORA metrics** dashboard (deployment frequency, lead time, change failure rate, MTTR)
- [ ] **Cloud deployment** (managed Kubernetes) using the same Terraform modules
- [ ] Re-introduce a SIEM/SOAR layer (Wazuh/Shuffle) if a full SOC integration is wanted later

---

## 20. Known limitations

- **Signature verification in `ci`:** images built for pull requests are loaded locally and not signed, so Kyverno runs in `Audit` mode in the ephemeral cluster and in `Enforce` mode only for images published from `main`.
- **Private repositories:** the GitHub Security tab needs Advanced Security; otherwise SARIF is kept as artifacts.
- **Mock payment service:** no real payment data or provider is involved.
- **Single-node resources:** a laptop-scale cluster cannot show real scalability or HA behaviour.
- **ZAP coverage:** DAST only covers what the OpenAPI spec describes, and findings should be triaged manually.

---

## 21. Tool reference

| Tool | Category | Role in this project |
|---|---|---|
| **Dapr** | Runtime | Microservice building blocks (invocation, pub/sub, state, secrets, bindings, mTLS) |
| **Kubernetes** (kind/k3s) | Orchestration | Runs the platform |
| **Helm** | Packaging | Deploys services and third-party components |
| **Terraform** | IaC | Cluster and platform provisioning |
| **Ansible** | Config management | Host bootstrap and hardening |
| **GitHub Actions** | CI/CD | Pipeline orchestration |
| **Gitleaks** | Secret scanning | Finds committed credentials |
| **Semgrep** | SAST | Insecure code patterns |
| **pip-audit** | SCA | Vulnerable Python dependencies |
| **Hadolint** | Linting | Dockerfile quality and security |
| **Trivy** | Scanner | Container image and IaC misconfiguration scanning |
| **Syft** | SBOM | CycloneDX bill of materials per build |
| **Cosign** | Supply chain | Image signing and SBOM attestation |
| **Kyverno** | Policy engine | Admission control in the cluster |
| **OWASP ZAP** | DAST | Dynamic testing of the deployed API |
| **Prometheus / Grafana** | Observability | Metrics and dashboards |
| **GitHub Security tab** | Findings | Central SARIF-based dashboard |

---

## 22. License

Released under the [MIT License](LICENSE).
