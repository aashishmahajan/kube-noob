---
id: rosa-hcp-lifecycle
title: ROSA with HCP cluster lifecycle
tags: [rosa, rosa-hcp, hcp, console, subnets, tags, upgrade, break-glass, external-auth, oidc, delete, operator-roles]
platforms: [rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [rosa, rosa-hcp, hcp, hosted, break-glass, break-glass-credential, oidc-provider, operator-roles, internal-elb, kubernetes.io/role/elb, kubernetes.io/role/internal-elb]
sources:
  - {title: "OpenShift docs: Verify access to the web console for a cluster in ready state", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-hcp-ready-no-console-access.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Tag your subnets", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-hcp-vpc-subnet-tagging.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Upgrade the hosted control plane with the rosa CLI", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-hcp-upgrading-cli-control-plane.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Create a break glass credential", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-hcp-sts-creating-a-break-glass-cred-cli.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Delete a cluster and the cluster-specific IAM resources", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-hcp-deleting-cluster.adoc", license: Apache-2.0}
---
# ROSA with HCP: cluster tasks from install to deletion

## Cluster is ready but the web console does not open

A ROSA with HCP cluster reports `ready` as soon as its hosted control plane, which runs in the ROSA service's account,
is ready. The web console runs as workloads on the cluster's own worker nodes, so it cannot be reached until the
workers have joined the cluster and the console workloads are running. Wait for the worker nodes, then open the
console again. To follow the nodes, log in to the cluster or use `rosa describe machinepool`.

## Tag subnets in your own VPC: kubernetes.io/role/elb and kubernetes.io/role/internal-elb

When you create the VPC yourself, its subnets need these tags; the service's preflight checks look for them before the
subnets can be used for a cluster. Tag at least one private subnet and, where it applies, one public subnet:

- public subnet: key `kubernetes.io/role/elb`, value `1` (or no value)
- private subnet: key `kubernetes.io/role/internal-elb`, value `1` (or no value)

```sh
aws ec2 create-tags --resources <public-subnet-id> --region <aws_region> --tags Key=kubernetes.io/role/elb,Value=1
aws ec2 create-tags --resources <private-subnet-id> --region <aws_region> --tags Key=kubernetes.io/role/internal-elb,Value=1
```

`aws ec2 describe-tags --filters "Name=resource-id,Values=<subnet_id>"` shows the tags a subnet carries. An install
that fails with `OCM5010` (failed to tag subnets) points to these tags or to the AWS permissions.

## Schedule a control plane upgrade: rosa list upgrade and rosa upgrade cluster --schedule-date

The hosted control plane is upgraded on its own, separately from the machine pools, and without disturbing the
workloads on the worker nodes. Make sure no machine pool update is running or scheduled for the same time. The control
plane supports machine pools up to two minor versions older: a 4.17.z control plane works with 4.15.z and 4.16.z
machine pools, not with 4.14.z.

1. Current version: `rosa describe cluster --cluster=<cluster_name_or_id>`.
2. Versions you can move to (the recommended one is marked): `rosa list upgrade --cluster=<cluster_name_or_id>`.
3. Update channel, if needed: `rosa edit cluster -c <cluster_name_or_id> --channel <channel>` (for example
   `rosa edit cluster -c <cluster_name_or_id> --channel stable-4.19`).
4. Upgrade now: `rosa upgrade cluster -c <cluster_name_or_id> --version <version_number>`.
   Or schedule it:
   `rosa upgrade cluster -c <cluster_name_or_id> --schedule-date=<yyyy-mm-dd> --schedule-time=<HH:mm> --version=<version_number>`.

The schedule date and time are in UTC. If a scheduled upgrade never starts, see the Red Hat solution "Upgrade
maintenance canceled" (https://access.redhat.com/solutions/6648291).

## Break glass credential for external OIDC: rosa create break-glass-credential

On a cluster that uses an external authentication provider (a custom OIDC token issuer), a break glass credential
gives you a temporary cluster-admin `kubeconfig`. You need an account with cluster admin permissions, and the external
authentication provider must already exist.

- Interactive: `rosa create break-glass-credential -c <cluster_name> -i`. An empty username gets a random one; an empty
  expiration means 24 hours.
- With values, for a cluster called `mycluster`:
  `rosa create break-glass-credential -c mycluster --username test-username --expiration 1h`.
- The credential is valid for at least 10 minutes and at most 24 hours.
- `rosa list break-glass-credential -c mycluster` lists the IDs, users and status (add `-o json` for JSON).

Write the `kubeconfig` to a file and use it:

```sh
mkdir ~/kubeconfigs
export CLUSTER_NAME=<cluster_name> && export KUBECONFIG=~/kubeconfigs/break-glass-${CLUSTER_NAME}.kubeconfig
rosa describe break-glass-credential <break_glass_credential_id> -c mycluster --kubeconfig > $KUBECONFIG
```

`rosa describe break-glass-credential <break_glass_credential_id> -c <cluster_name>` shows the status: `issued` (ready
to use), `expired`, `failed` (a service log gives the reason), `awaiting_revocation` (being revoked, not usable) or
`revoked`.

## Delete a cluster, then its operator roles and OIDC provider

Delete the cluster first and wait until the deletion has finished; only then remove the cluster-specific operator roles
and the OIDC provider, because the deletion and its clean-up still use them. Removing them afterwards avoids leaving
unused IAM resources in the AWS account.

1. `rosa describe cluster --cluster=<cluster_name>`: note the `ID`, the `Operator IAM Roles` ARNs and the
   `OIDC Endpoint URL`. You need the cluster ID to remove the STS resources once the cluster is gone.
2. If deletion protection is on: `rosa edit cluster -c <cluster_name> --enable-delete-protection=false`.
3. `rosa delete cluster --cluster=<cluster_name> --watch` (or Delete cluster in OpenShift Cluster Manager). Installed
   add-ons are removed first, so deletion takes longer with add-ons.
4. Operator roles: `rosa delete operator-roles --prefix <operator_role_prefix>`; on a shared VPC use
   `rosa delete operator-roles --prefix <operator_role_prefix> --delete-hosted-shared-vpc-policies`.
5. OIDC provider: `rosa delete oidc-provider --oidc-config-id <oidc_config_id>`.

If something is left over, look for pending add-ons in the Hybrid Cloud Console and for remaining resources in the
AWS console. If the deletion is refused with `sts_user_role is not linked to your account`, run `rosa create user-role`
and delete again.
