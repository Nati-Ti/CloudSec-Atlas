# Generic Flat Network Without Segmentation

A cloud application runs web servers, worker nodes, and a database in a single subnet with broad internal firewall rules. The team describes the network as flat because it was simpler during early development.

The web tier is internet-facing, the database stores customer records, and administrative access is handled through the same subnet. Logging is not centralized, and there are no network flow logs or lateral-movement alerts.
