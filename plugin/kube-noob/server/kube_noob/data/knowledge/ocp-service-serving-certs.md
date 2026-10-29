---
id: ocp-service-serving-certs
title: Service serving certificate secrets
tags: [openshift, service-ca, certificates, secrets, tls, serving-cert]
platforms: [openshift]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [serving-cert-generation-error, serving-cert-generation-error-num, serving-cert-secret-name, serviceuid, service-ca, serving, service.beta.openshift.io]
sources:
  - {title: "OpenShift docs: Troubleshoot secrets", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/nodes-pods-secrets-troubleshooting.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: About using signed certificates with secrets", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/nodes-pods-secrets-certificates-about.adoc", license: Apache-2.0}
---
# Service serving certificate secrets

## Service serving certificate secrets (service.beta.openshift.io/serving-cert-secret-name)

OpenShift can generate a signed serving certificate and key for a Service and store them in a secret in the
project. Annotate the Service with the secret name you want:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: registry
  annotations:
    service.beta.openshift.io/serving-cert-secret-name: registry-cert
```

These certificates are signed only for internal DNS names. Other pods can trust them through the CA bundle mounted
automatically as `service-ca.crt` with each pod's service account files. To rotate one by hand, delete the
generated secret and a new certificate is created.

## serving-cert-generation-error: secret references serviceUID which does not match

When generating the certificate fails, the Service's `service.beta.openshift.io/serving-cert-generation-error`
annotation holds the reason, for example:

```
secret/ssl-key references serviceUID 62ad25ca-d703-11e6-9d6f-0e9c0057b608, which does not match 77b6dd80-d716-11e6-9d6f-0e9c0057b60
```

The Service that generated the certificate is gone, or now has a different `serviceUID`. Force a new certificate:
remove the old secret, then clear both error annotations on the Service (a `-` after an annotation name removes it):

```sh
oc delete secret <secret_name>
oc annotate service <service_name> service.beta.openshift.io/serving-cert-generation-error-
oc annotate service <service_name> service.beta.openshift.io/serving-cert-generation-error-num-
```
