# Network Security Manager

NSM help manage network policies on a kubernetes cluster in an easy and effective way.
Its NetworkPolicyExporter can translate cluster networkpolicies into format that resemble a zoned firewall rules list.

# Building and pushing the operator images

Use the supplied makefile:

```
make
```

# Executing

make sure your KUBECONFIG points to the correct cluster and run the utility with user that have permissions to read networkpolicies.
that it.

output generated on stdout can be redirected to a file for further consumption.
