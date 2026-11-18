# The local example: agent-facing gateway, two policy engines, the egress proxy, Vault in dev mode and a pretend
# outside API. Each link runs on its own network; only the gateway's port is published, on 127.0.0.1.
#   terraform init && terraform apply
# Certificates, secrets and logs go to var.run_dir, outside git.

terraform {
  required_version = ">= 1.6"
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 4.7" }
  }
}

provider "docker" {}

variable "run_dir" {
  type        = string
  description = "Certificates, example secrets and the gateway's logs (kept out of git)."
  default     = null
}

variable "max_connections" {
  type        = number
  default     = 64
  description = "Connections the gateway handles at once; more are closed at once."
}

variable "gateway_port" {
  type    = number
  default = 8443
}

locals {
  here = abspath(path.module)
  repo = abspath("${path.module}/../../..")
  run  = coalesce(var.run_dir, "${local.repo}/run")
  images = {
    opa     = "openpolicyagent/opa@sha256:ff50f50332ff9e722ffafe2658c195ced1f9b6d4f3064000c2ecfa8cdf7acccf"
    opaenvo = "openpolicyagent/opa@sha256:6ce6563695665a4c06338832e0a532c4dbf16f7beea05386ad0a6eb91d9e8593"
    envoy   = "envoyproxy/envoy@sha256:1fde8efee875e4e4f6a39a90fe49d9338e1caacce5762034ef9fb4bbb9ad6aed"
    vault   = "hashicorp/vault@sha256:dfa48c2fa2b0099ccb47681ec5c4804bf5aec9d6879ecfee07ad4b92a5427ad6"
    python  = "python@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
  }
}

# --- preparation: certificates, example secrets, the gateway image ---

resource "terraform_data" "stage" {
  input = local.run
  provisioner "local-exec" {
    command = "sh '${local.here}/scripts/stage.sh' '${local.run}'"
  }
}

resource "terraform_data" "gateway_image" {
  triggers_replace = [sha1(join("", [for f in fileset("${local.repo}/src", "**/*.py") : filesha1("${local.repo}/src/${f}")]))]
  provisioner "local-exec" {
    command = "sh '${local.here}/scripts/build-gateway.sh' airlock-gateway:local"
  }
}

resource "docker_image" "img" {
  for_each     = local.images
  name         = each.value
  keep_locally = true
}

# --- networks: one per link ---

resource "docker_network" "front" { # publishes the gateway's port; no outbound NAT, so no internet from here
  name    = "airlock-front"
  options = { "com.docker.network.bridge.enable_ip_masquerade" = "false" }
}

resource "docker_network" "internal" {
  for_each = toset(["policy", "vault", "egress", "egress-policy", "demo"])
  name     = "airlock-${each.key}"
  internal = true
}

resource "docker_network" "outside" { # the egress proxy's way to the internet
  name = "airlock-outside"
}

# --- the first door: tools policy ---

resource "docker_container" "opa_tools" {
  name        = "airlock-opa-tools"
  image       = docker_image.img["opa"].image_id
  read_only   = true
  user        = "1000:1000"
  memory      = 128 # MB; the kernel stops this container, not the host, when it is exceeded
  memory_swap = 128 # the same number: no swap
  cpus        = "0.5"
  log_opts    = { "max-size" = "10m", "max-file" = "3" } # Docker's own log of the container stays small
  ulimit {
    name = "nofile"
    soft = 4096
    hard = 4096
  }
  security_opts = ["no-new-privileges:true"]
  capabilities { drop = ["ALL"] }
  command = ["run", "--server", "--addr=0.0.0.0:8181", "--log-level=error",
    "--tls-cert-file=/certs/opa-tools.pem", "--tls-private-key-file=/certs/opa-tools-key.pem",
    "--tls-ca-cert-file=/certs/ca.pem", "--authentication=tls", "--authorization=basic",
  "/policy/tools.rego", "/policy/data.json", "/authz/authz.rego"]
  volumes {
    host_path      = "${local.run}/certs/opa-tools"
    container_path = "/certs"
    read_only      = true
  }
  volumes {
    host_path      = "${local.repo}/policies/tools"
    container_path = "/policy"
    read_only      = true
  }
  volumes {
    host_path      = "${local.repo}/policies/opa-system"
    container_path = "/authz"
    read_only      = true
  }
  networks_advanced {
    name    = docker_network.internal["policy"].name
    aliases = ["opa-tools"]
  }
  depends_on = [terraform_data.stage]
}

# --- the second door: egress proxy and its policy ---

resource "docker_container" "opa_egress" {
  name        = "airlock-opa-egress"
  image       = docker_image.img["opaenvo"].image_id
  read_only   = true
  user        = "1000:1000"
  memory      = 128 # MB; the kernel stops this container, not the host, when it is exceeded
  memory_swap = 128 # the same number: no swap
  cpus        = "0.5"
  log_opts    = { "max-size" = "10m", "max-file" = "3" } # Docker's own log of the container stays small
  ulimit {
    name = "nofile"
    soft = 4096
    hard = 4096
  }
  security_opts = ["no-new-privileges:true"]
  capabilities { drop = ["ALL"] }
  command = ["run", "--server", "--addr=127.0.0.1:8181", "--log-level=error", "--config-file=/config/opa-egress.yaml",
  "/policy/egress.rego", "/policy/data.json"]
  volumes {
    host_path      = "${local.repo}/policies/egress"
    container_path = "/policy"
    read_only      = true
  }
  volumes {
    host_path      = "${local.here}/envoy/opa-egress.yaml"
    container_path = "/config/opa-egress.yaml"
    read_only      = true
  }
  networks_advanced {
    name    = docker_network.internal["egress-policy"].name
    aliases = ["opa-egress"]
  }
}

resource "docker_container" "egress" {
  name        = "airlock-egress"
  image       = docker_image.img["envoy"].image_id
  read_only   = true
  user        = "101:101"
  memory      = 128 # MB; the kernel stops this container, not the host, when it is exceeded
  memory_swap = 128 # the same number: no swap
  cpus        = "0.5"
  log_opts    = { "max-size" = "10m", "max-file" = "3" } # Docker's own log of the container stays small
  ulimit {
    name = "nofile"
    soft = 4096
    hard = 4096
  }
  security_opts = ["no-new-privileges:true"]
  capabilities { drop = ["ALL"] }
  command = ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "warn"]
  volumes {
    host_path      = "${local.here}/envoy/envoy.yaml"
    container_path = "/etc/envoy/envoy.yaml"
    read_only      = true
  }
  volumes {
    host_path      = "${local.run}/certs/egress"
    container_path = "/certs"
    read_only      = true
  }
  networks_advanced {
    name    = docker_network.internal["egress"].name
    aliases = ["egress"]
  }
  networks_advanced { name = docker_network.internal["egress-policy"].name }
  networks_advanced { name = docker_network.internal["demo"].name }
  networks_advanced { name = docker_network.outside.name }
  depends_on = [terraform_data.stage, docker_container.opa_egress]
}

# --- secrets: Vault in dev mode with a TLS listener that requires client certificates ---

resource "docker_container" "vault" {
  name        = "airlock-vault"
  image       = docker_image.img["vault"].image_id
  read_only   = true
  memory      = 256 # MB; the kernel stops this container, not the host, when it is exceeded
  memory_swap = 256 # the same number: no swap
  cpus        = "0.5"
  log_opts    = { "max-size" = "10m", "max-file" = "3" } # Docker's own log of the container stays small
  ulimit {
    name = "nofile"
    soft = 4096
    hard = 4096
  }
  security_opts = ["no-new-privileges:true"]
  capabilities { drop = ["ALL"] }
  env     = ["SKIP_SETCAP=true", "SKIP_CHOWN=true", "VAULT_DISABLE_MLOCK=true", "HOME=/vault/home"]
  command = ["server", "-dev", "-dev-listen-address=127.0.0.1:8201", "-config=/vault/extra/tls.hcl"]
  tmpfs   = { "/vault/home" = "rw,size=1m,uid=100", "/vault/file" = "rw,size=1m,uid=100", "/vault/logs" = "rw,size=1m,uid=100", "/tmp" = "rw,size=8m" }
  volumes {
    host_path      = "${local.here}/vault"
    container_path = "/vault/extra"
    read_only      = true
  }
  volumes {
    host_path      = "${local.run}/certs/vault"
    container_path = "/certs"
    read_only      = true
  }
  volumes {
    host_path      = "${local.run}/secrets-vault"
    container_path = "/secrets"
    read_only      = true
  }
  networks_advanced {
    name    = docker_network.internal["vault"].name
    aliases = ["vault"]
  }
  depends_on = [terraform_data.stage]
}

resource "terraform_data" "vault_init" {
  triggers_replace = [docker_container.vault.id]
  provisioner "local-exec" {
    command = "docker exec airlock-vault sh /vault/extra/init.sh"
  }
}

# --- a pretend outside API, reachable only through the egress proxy ---

resource "docker_container" "demo_api" {
  name        = "airlock-demo-api"
  image       = docker_image.img["python"].image_id
  read_only   = true
  user        = "10002:10002"
  memory      = 64 # MB; the kernel stops this container, not the host, when it is exceeded
  memory_swap = 64 # the same number: no swap
  cpus        = "0.25"
  log_opts    = { "max-size" = "10m", "max-file" = "3" } # Docker's own log of the container stays small
  ulimit {
    name = "nofile"
    soft = 4096
    hard = 4096
  }
  security_opts = ["no-new-privileges:true"]
  capabilities { drop = ["ALL"] }
  command = ["python", "-u", "/app/demo_api.py"]
  volumes {
    host_path      = "${local.here}/demo-api"
    container_path = "/app"
    read_only      = true
  }
  volumes {
    host_path      = "${local.run}/certs/demo-api"
    container_path = "/certs"
    read_only      = true
  }
  volumes {
    host_path      = "${local.run}/secrets-demo"
    container_path = "/secrets"
    read_only      = true
  }
  networks_advanced {
    name    = docker_network.internal["demo"].name
    aliases = ["demo-api"]
  }
  depends_on = [terraform_data.stage]
}

# --- the gateway ---

resource "docker_container" "gateway" {
  name        = "airlock-gateway"
  image       = "airlock-gateway:local"
  read_only   = true
  user        = "10001:10001"
  memory      = 256 # MB; the kernel stops this container, not the host, when it is exceeded
  memory_swap = 256 # the same number: no swap
  cpus        = "1.0"
  log_opts    = { "max-size" = "10m", "max-file" = "3" } # Docker's own log of the container stays small
  ulimit {
    name = "nofile"
    soft = 4096
    hard = 4096
  }
  security_opts = ["no-new-privileges:true"]
  capabilities { drop = ["ALL"] }
  env = [
    "AIRLOCK_CERT=/certs/gateway.pem", "AIRLOCK_KEY=/certs/gateway-key.pem", "AIRLOCK_CA=/certs/ca.pem",
    "AIRLOCK_OPA_URL=https://opa-tools:8181", "AIRLOCK_VAULT_URL=https://vault:8200",
    "AIRLOCK_EGRESS_URL=https://egress:10000", "AIRLOCK_CONFIG=/config/gateway.json", "AIRLOCK_LOG_DIR=/logs",
    "AIRLOCK_MAX_CONNECTIONS=${var.max_connections}",
  ]
  ports {
    internal = 8443
    external = var.gateway_port
    ip       = "127.0.0.1"
  }
  volumes {
    host_path      = "${local.run}/certs/gateway"
    container_path = "/certs"
    read_only      = true
  }
  volumes {
    host_path      = "${local.here}/config"
    container_path = "/config"
    read_only      = true
  }
  volumes {
    host_path      = "${local.run}/logs"
    container_path = "/logs"
  }
  networks_advanced { name = docker_network.front.name }
  networks_advanced { name = docker_network.internal["policy"].name }
  networks_advanced { name = docker_network.internal["vault"].name }
  networks_advanced { name = docker_network.internal["egress"].name }
  depends_on = [terraform_data.gateway_image, terraform_data.vault_init, docker_container.opa_tools, docker_container.egress]
  lifecycle {
    replace_triggered_by = [terraform_data.gateway_image] # a new image means a new container
  }
}

output "try_it" {
  value = "curl --cert ${local.run}/pki/agent.pem --key ${local.run}/pki/agent-key.pem --cacert ${local.run}/pki/ca.pem https://localhost:${var.gateway_port}/healthz"
}
