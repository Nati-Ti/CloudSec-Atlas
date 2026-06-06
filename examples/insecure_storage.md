# Insecure Storage Scenario

An Azure analytics team stores monthly customer exports in a Blob Storage account.
The storage container has public blob access enabled so contractors can download files
without VPN access.

Some exports include email addresses, internal account IDs, and support history.
The team uses a shared access key that is copied into a local .env file for scripts.
Encryption is enabled by default, but logging and alerting for blob reads are not configured.

The analytics dashboard is hosted as an App Service with a public API.
