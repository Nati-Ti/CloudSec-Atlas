# Azure Key Vault Secret Exposure

An Azure App Service uses a managed identity to read secrets from Key Vault, but a deployment script also copies a database password and storage connection string into a local .env file for troubleshooting.

The App Service exposes a public API used by internal support users. Key Vault access logs are not monitored, Defender for Cloud is not enabled, and there is no alerting for secret reads or role assignment changes.
