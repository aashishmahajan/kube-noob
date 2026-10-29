"""Build insight (requirements R4): from a failed build log to the cause and the fix (``kube_noob.build.logs``), and
a static audit of Containerfiles and images on disk (``kube_noob.build.containerfile``, ``kube_noob.build.oci``).

Everything here reads text or files the user gives it; nothing runs a build, pulls an image or calls a CI system.
"""
