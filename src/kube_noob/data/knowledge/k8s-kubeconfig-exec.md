---
id: k8s-kubeconfig-exec
title: kubeconfig credential plugins (exec) and "executable not found"
tags: [kubernetes, openshift, kubectl, kubeconfig, authentication, exec, credentials, troubleshooting]
platforms: [kubernetes, openshift, rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [kubeconfig, credential, credentials, installhint, get-token, kubelogin, exec-plugin]
sources:
  - {title: "Kubernetes: Authenticating (client-go credential plugins)", url: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins", license: CC-BY-4.0}
---
# kubeconfig credential plugins

A kubeconfig user can get its credentials by running a program: under `users[].user.exec`, `command` (required),
`args`, `env`, `apiVersion` (`client.authentication.k8s.io/v1`), `interactiveMode` and an optional `installHint`.
kubectl and the other tools built on client-go run that command and authenticate with the credential it prints.

## "executable ... not found" when kubectl or a tool connects

The kubeconfig names a program that the tool running it cannot find. Read the `exec` block
(`kubectl config view --minify`), then:

1. Install that program on the machine where the tool runs. A kubeconfig copied to another machine (from WSL to
   Windows, from a laptop to a CI runner) carries only the reference, never the program; the `installHint` text,
   when the kubeconfig has one, says how to install it.
2. Make it findable by the tool that runs it: a bare name is looked up on that program's `PATH`, which for a
   desktop app can differ from your shell's. Or set `command` to an absolute path.
3. A relative path in `command` is resolved from the kubeconfig file's directory, not the current directory.

Older kubectl releases had built-in sign-in for AKS and GKE; current ones do not, so those clusters also use an
exec plugin.
