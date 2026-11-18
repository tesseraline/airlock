# Added to Vault's dev mode: a TLS listener that requires a client certificate from the example CA.
disable_mlock = true
listener "tcp" {
  address                            = "0.0.0.0:8200"
  tls_cert_file                      = "/certs/vault.pem"
  tls_key_file                       = "/certs/vault-key.pem"
  tls_client_ca_file                 = "/certs/ca.pem"
  tls_require_and_verify_client_cert = "true"
}
