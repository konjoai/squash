# Kong squash-attest plugin (Track B / B5)

Generate the plugin source bundle and declarative config from
`squash/integrations/gateway.py` via:

```
squash gateway-config kong --emit-plugin --output integrations/kong/squash-attest/
squash gateway-config kong --output kong-config.yaml
```

See `squash gateway-config --help` for the full option matrix.
