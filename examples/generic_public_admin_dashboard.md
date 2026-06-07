# Generic Public Admin Dashboard

A cloud-hosted admin dashboard is exposed on a public endpoint so operations staff can manage customer accounts. The dashboard has no MFA requirement and uses a shared administrator account.

The app connects to a backend database that stores account records and support notes. Logging is limited to application errors, and there is no WAF, rate limiting, or alerting on unusual admin actions.
