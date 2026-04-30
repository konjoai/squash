# AWS API Gateway authorizer for squash-attest (Track B / B5)

Generate the SAM template + Lambda handler from
`squash/integrations/gateway.py` via:

```
squash gateway-config aws-apigw --output template.yaml
squash gateway-config aws-apigw --emit-authorizer-dir --output authorizer/
```

See `squash gateway-config --help` for the full option matrix.
