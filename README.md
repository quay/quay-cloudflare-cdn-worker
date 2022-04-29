# Quay CloudFlare CDN worker

CloudFlare worker which verifies signed URLs from quay for serving blobs and
manifests

# Development

You need to install and setup the CloudFlare CLI tool
[`wrangler`](https://developers.cloudflare.com/workers/cli-wrangler/)

Update the `wrangler.toml` with your config and run the following commands

```bash
wrangler build
wrangler publish
```

This updates the worker on CloudFlare. If you want to view the logs you can run 

```bash
wrangler tail --format=pretty
```
