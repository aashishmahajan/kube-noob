"""Input model for the generator (Step 6) and the clarification gate (Step 1)."""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

from kube_noob.catalog import DEFAULT_STORAGE_CLASS, OPENSHIFT_FAMILY, ROSA_FAMILY

_NAME = re.compile(r"^[a-z]([-a-z0-9]{0,51}[a-z0-9])?$")
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/%-]*$")
_HOST = re.compile(r"^(\*\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$")
_QTY = re.compile(r"^\d+(\.\d+)?(m|Ki|Mi|Gi|Ti|k|M|G|T)?$")
# IANA_SVC_NAME (container/service port names): <= 15 chars, lowercase alphanumerics and '-', at least one letter,
# no leading/trailing or consecutive hyphens.
_PORT_NAME = re.compile(r"^(?=.*[a-z])(?!.*--)[a-z0-9]([-a-z0-9]{0,13}[a-z0-9])?$")


def _cidr(v: str) -> str:
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid CIDR {v!r}: {exc}") from exc


class _Base(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, extra="forbid", str_strip_whitespace=True
    )


class Resources(_Base):
    cpu_request: str = "100m"
    memory_request: str = "128Mi"
    cpu_limit: str | None = None
    memory_limit: str = "256Mi"

    @field_validator("cpu_request", "memory_request", "cpu_limit", "memory_limit")
    @classmethod
    def _qty(cls, v: str | None) -> str | None:
        if v is not None and not _QTY.match(v):
            raise ValueError(f"invalid resource quantity {v!r}")
        return v


class Storage(_Base):
    size: str = Field("10Gi", description="PVC size, e.g. 10Gi")
    access_mode: Literal["ReadWriteOnce", "ReadWriteMany", "ReadWriteOncePod"] = "ReadWriteOnce"
    storage_class: str | None = Field(None, description="StorageClass name; platform default chosen when omitted")
    mount_path: str = "/data"

    @field_validator("size")
    @classmethod
    def _size(cls, v: str) -> str:
        if not _QTY.match(v):
            raise ValueError(f"invalid storage size {v!r}")
        return v


class Exposure(_Base):
    type: Literal["none", "route", "ingress", "gateway", "loadbalancer"] = "none"
    host: str | None = None
    path: str = "/"
    tls: Literal["edge", "reencrypt", "passthrough"] = "edge"
    ingress_class: str | None = None
    tls_secret: str | None = Field(None, description="Ingress TLS secret name (cert-manager can create it)")
    gateway_name: str | None = None
    gateway_namespace: str | None = None
    lb_source_ranges: list[str] = Field(default_factory=list)
    internal_lb: bool = True

    @field_validator("lb_source_ranges")
    @classmethod
    def _ranges(cls, v: list[str]) -> list[str]:
        return [_cidr(x) for x in v]

    @field_validator("host")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        if v is not None and not _HOST.match(v.lower()):
            raise ValueError(f"invalid host name {v!r}")
        return v.lower() if v else v

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not _PATH.match(v):
            raise ValueError(f"invalid HTTP path {v!r}")
        return v


class Blueprint(_Base):
    name: str = Field(..., description="DNS-1123 label, e.g. 'orders-api'")
    namespace: str = Field(..., description="Target namespace / OpenShift project")
    image: str = Field(..., description="Container image, ideally pinned by digest")
    platform: Literal["kubernetes", "openshift", "rosa-classic", "rosa-hcp"] = "kubernetes"
    platform_version: str | None = None
    workload: Literal["deployment", "statefulset"] = "deployment"
    replicas: int = Field(3, ge=1, le=100)
    port: int = Field(8080, ge=1, le=65535)
    port_name: str = "http"
    probe: Literal["http", "tcp", "none"] = "http"
    liveness_path: str = "/healthz"
    readiness_path: str = "/readyz"
    startup_seconds: int = Field(0, ge=0, le=600, description="Add a startupProbe allowing this many seconds")
    resources: Resources = Field(default_factory=Resources)
    storage: Storage | None = None
    exposure: Exposure = Field(default_factory=Exposure)
    env: dict[str, str] = Field(default_factory=dict)
    secret_env: dict[str, str] = Field(
        default_factory=dict, description="ENV_NAME -> 'secretName/key' references (values never inlined)"
    )
    egress: Literal["open", "dns-only", "cidrs"] = "open"
    egress_cidrs: list[str] = Field(default_factory=list)
    egress_dns_names: list[str] = Field(default_factory=list, description="OpenShift EgressFirewall allow list")
    hpa_max_replicas: int | None = Field(None, ge=2, le=1000)
    read_only_root_fs: bool = True
    writable_paths: list[str] = Field(default_factory=lambda: ["/tmp"])  # noqa: S108 - emptyDir mount, not host /tmp
    run_as_user: int | None = Field(None, ge=1, description="Fixed UID (vanilla Kubernetes only)")
    allow_monitoring: bool = True
    create_namespace: bool = False

    @field_validator("name", "namespace")
    @classmethod
    def _dns(cls, v: str) -> str:
        if not _NAME.match(v) or len(v) > 53:
            raise ValueError(f"{v!r} must be a lowercase DNS-1123 label (max 53 chars), e.g. 'orders-api'")
        return v

    @field_validator("port_name")
    @classmethod
    def _port_name(cls, v: str) -> str:
        if not _PORT_NAME.match(v):
            raise ValueError(
                f"portName {v!r} must be an IANA service name: max 15 lowercase letters/digits/'-', at least one "
                "letter, no leading, trailing or double hyphens (e.g. 'http', 'grpc-api')"
            )
        return v

    @field_validator("egress_cidrs")
    @classmethod
    def _egress_cidrs(cls, v: list[str]) -> list[str]:
        return [_cidr(x) for x in v]

    @field_validator("image")
    @classmethod
    def _image(cls, v: str) -> str:
        if not v or " " in v or len(v) > 512:
            raise ValueError("image must be a valid reference like 'quay.io/org/app:1.2.3' or 'repo@sha256:...'")
        return v

    @field_validator("env")
    @classmethod
    def _env(cls, v: dict[str, str]) -> dict[str, str]:
        from kube_noob.audit.rules import SENSITIVE_ENV

        for k in v:
            if SENSITIVE_ENV.search(k):
                raise ValueError(f"env {k!r} looks like a secret; pass it via secretEnv as 'secretName/key'")
        return v

    @field_validator("secret_env")
    @classmethod
    def _secret_env(cls, v: dict[str, str]) -> dict[str, str]:
        for k, ref in v.items():
            if ref.count("/") != 1 or not all(ref.split("/")):
                raise ValueError(f"secretEnv[{k}] must be 'secretName/key', got {ref!r}")
        return v

    @model_validator(mode="after")
    def _platform_rules(self) -> Blueprint:
        if self.run_as_user is not None and self.platform in OPENSHIFT_FAMILY:
            raise ValueError("runAsUser must not be fixed on OpenShift/ROSA: restricted-v2 assigns UIDs per namespace")
        if self.exposure.type == "route" and self.exposure.host and self.exposure.host.startswith("*."):
            raise ValueError(
                "Route hosts cannot contain '*'. Wildcard Routes need wildcardPolicy: Subdomain with a concrete host "
                "(e.g. 'wildcard.apps.example.com') and an IngressController that allows wildcards; use a normal host "
                "or exposure.type 'ingress'/'gateway' for a '*.' host."
            )
        return self


def clarify(bp: Blueprint) -> tuple[list[str], list[str]]:
    """Return (blocking questions, stated assumptions)."""
    q: list[str] = []
    a: list[str] = []
    is_ocp = bp.platform in OPENSHIFT_FAMILY
    ex = bp.exposure
    if ex.type == "route" and not is_ocp:
        q.append(
            "Routes only exist on OpenShift. Use exposure.type 'ingress' or 'gateway' for vanilla Kubernetes, "
            "or set platform to openshift / rosa-hcp / rosa-classic."
        )
    if ex.type == "gateway" and not ex.gateway_name:
        q.append("Which Gateway should the HTTPRoute attach to? Set exposure.gatewayName (and gatewayNamespace).")
    if ex.type == "ingress" and not ex.host:
        q.append("Ingress needs a host for TLS. Set exposure.host (e.g. orders.apps.example.com).")
    if ex.type == "loadbalancer" and not ex.internal_lb and not ex.lb_source_ranges:
        q.append(
            "A public LoadBalancer without source ranges is reachable from the internet. Provide "
            "exposure.lbSourceRanges or keep internalLb: true."
        )
    st = bp.storage
    if st is not None:
        default_sc = DEFAULT_STORAGE_CLASS[bp.platform].get(
            st.access_mode if st.access_mode != "ReadWriteOncePod" else "ReadWriteOnce"
        )
        if st.access_mode == "ReadWriteMany" and not st.storage_class and default_sc is None:
            q.append(
                "ReadWriteMany needs a shared-filesystem StorageClass (NFS, CephFS, EFS, Azure Files). Which "
                "StorageClass should be used? Set storage.storageClass."
            )
        if st.access_mode != "ReadWriteMany" and bp.workload == "deployment" and bp.replicas > 1:
            q.append(
                f"{bp.replicas} replicas cannot share a {st.access_mode} volume (Multi-Attach). Choose: "
                "workload 'statefulset' (one volume per replica), replicas: 1, or accessMode ReadWriteMany "
                "(only if the app supports concurrent writers)."
            )
        if st.access_mode == "ReadWriteMany" and bp.replicas > 1:
            a.append(
                "ReadWriteMany with several replicas: the application must handle concurrent writers "
                "(no embedded databases on shared storage)."
            )
        if not st.storage_class and default_sc:
            a.append(f"storage.storageClass not set; using platform default '{default_sc}'.")
            if bp.platform in ROSA_FAMILY and default_sc == "efs-sc":
                a.append(
                    "efs-sc requires the AWS EFS CSI Driver Operator and an EFS file system with mount targets "
                    "in every worker subnet (prerequisite, not generated)."
                )
    if bp.egress == "cidrs" and not bp.egress_cidrs:
        q.append("egress: cidrs requires egressCidrs.")
    if bp.egress_dns_names and not is_ocp:
        q.append("egressDnsNames uses OpenShift EgressFirewall; on vanilla Kubernetes use egress CIDRs instead.")
    if bp.platform_version is None:
        a.append(f"platformVersion not set; generating for the newest supported {bp.platform} release.")
    tag_part = bp.image.split("@", 1)[0].rsplit("/", 1)[-1]
    if "@sha256:" not in bp.image and (":" not in tag_part or tag_part.endswith(":latest")):
        a.append(f"Image '{bp.image}' is not pinned; pin a version tag or digest before production.")
    if bp.probe == "http":
        a.append(
            f"HTTP probes assume the app serves {bp.liveness_path} (liveness) and {bp.readiness_path} "
            f"(readiness) on port {bp.port}."
        )
    if bp.read_only_root_fs:
        a.append(f"readOnlyRootFilesystem: true with writable emptyDir mounts at {', '.join(bp.writable_paths)}.")
    if bp.platform not in OPENSHIFT_FAMILY and bp.run_as_user is None:
        a.append("runAsNonRoot: true without a fixed UID: the image must declare a numeric non-root USER.")
    return q, a
