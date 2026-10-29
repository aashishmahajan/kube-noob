---
id: rosa-troubleshooting
title: ROSA install and network troubleshooting
tags: [rosa, rosa-hcp, install, logs, quota, aws, nlb, ingress]
platforms: [rosa-classic, rosa-hcp]
updated: 2026-10-28
license: Apache-2.0
requires:
  - [rosa, rosa-hcp, hcp, aws, nlb]
sources:
  - {title: "OpenShift docs: Installation troubleshooting (rosa logs install, rosa verify quota)", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-troubleshooting-installing.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Set up the environment for STS (rosa verify quota --region)", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-sts-setting-up-environment.adoc", license: Apache-2.0}
  - {title: "OpenShift docs: Connectivity issues on clusters with private network load balancers", url: "https://github.com/openshift/openshift-docs/blob/164957757519b01359989b533feac5ecab551530/modules/rosa-troubleshooting-networking-nlb.adoc", license: Apache-2.0}
---
# ROSA troubleshooting: installs and private network load balancers

## ROSA install stuck or failed: rosa logs install --watch and rosa verify quota

Start with the install log. `rosa logs install --cluster=<cluster_name>` prints it, and
`rosa logs install --cluster=<cluster_name> --watch` keeps streaming it while the install runs. For a cluster that is
being deleted, `rosa logs uninstall --cluster=<cluster_name>` shows the uninstall log, and
`rosa logs uninstall --cluster=<cluster_name> --watch` follows it.

Then check that the AWS account has enough quota: `rosa verify quota`. AWS sets quotas per region, so check the
region the cluster is created in: `rosa verify quota [--region=<aws_region>]`. When a service is short, request a
quota increase for that service in the AWS console, or try a different region.

## AWS email "Your Request For Accessing AWS Resources Has Been Validated"

Expected during cluster creation; nothing needs fixing. The ROSA service launches small instances in every supported
region to confirm that your AWS account can deploy to each of them. When the account does not use all of those
regions, AWS can send one or more of these emails, usually from aws-verification@amazon.com.

## Private NLB: pods on the same node as a router pod cannot reach the ingress load balancer

Clusters created on the current version use an AWS Network Load Balancer (NLB) by default for the `default` ingress
controller. A private NLB keeps the client IP address, and because of that a connection can be dropped when its
source and destination are the same host. Workloads running on a node that also runs a router pod can therefore fail
to reach routes through the private NLB. Move those workloads to nodes where no router pod runs, or have them reach
other workloads in the cluster over the internal pod and Service networks instead of the load balancer. AWS describes
the behaviour under "loopback timeout" in its Network Load Balancer troubleshooting guide
(https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-troubleshooting.html#loopback-timeout).
