# Serverless API Missing Authentication

A serverless API receives public requests through an API gateway and invokes cloud functions that read from object storage and a NoSQL database.

Several sensitive routes are unauthenticated because the prototype was originally used by one partner integration. The workflow stores partner data, report exports, and account IDs, but rate limiting and application-layer alerting are not configured.
