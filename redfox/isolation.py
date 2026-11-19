"""Per-tool container isolation.

The policy gate decides *whether* a tool runs. This decides *where*. When
`REDFOX_ISOLATE=docker` is set, a tool invocation becomes a `docker run` of an
image that contains only that tool, with the engagement's evidence directory as
the only mount. The host filesystem, the operator's credentials in `~/.ssh`, and
every other tool on the machine are out of reach.

What this does and does not buy:

- It contains the *toolchain*: a template that reads files, a wordlist that walks
  paths, or a compromised scanner cannot touch the workstation.
- The network is `REDFOX_DOCKER_NETWORK` (default `bridge`). That is outbound-only
  and cannot reach the loopback lab on the host; use `host` or a user-defined
  network when the target is local. It does not stop a scanner from following a
  redirect — that is still bounded by what the tool does, not by the mount.

An image that does not exist for a tool is not silently replaced by a host
execution: the task fails with `isolation.no_image` and the campaign records it.
Running unsandboxed has to be a decision the operator makes, not a fallback.
"""

from __future__ import annotations

import shutil
from pathlib import Path

# Images that contain the tool and nothing else worth compromising. Each was
# checked by running its version command against the image directly
# (`docker run --rm <image> <flag>`), because the wrapper relies on the image's
# entrypoint being the tool itself. `ffuf/ffuf` publishes no tags; `secsi/ffuf`
# does and reports `ffuf version: 2.3.0`.
IMAGES = {
    "nmap": "instrumentisto/nmap:latest",
    "nuclei": "projectdiscovery/nuclei:latest",
    "nuclei_validate": "projectdiscovery/nuclei:latest",
    "httpx": "projectdiscovery/httpx:latest",
    "subfinder": "projectdiscovery/subfinder:latest",
    "amass": "caffix/amass:latest",
    "ffuf": "secsi/ffuf:latest",
    "whatweb": "secsi/whatweb:latest",
    "sslscan": "secsi/sslscan:latest",
}
EVIDENCE_MOUNT = "/evidence"

# The nuclei image ships no templates, so a run without this volume scans nothing
# and reports nothing — a silent downgrade. `redfox isolate setup` populates it.
VOLUMES = {
    "nuclei": ("redfox-nuclei-templates", "/root/nuclei-templates"),
    "nuclei_validate": ("redfox-nuclei-templates", "/root/nuclei-templates"),
}
TEMPLATES_VOLUME = "redfox-nuclei-templates"
TEMPLATES_PATH = "/root/nuclei-templates"


class IsolationUnavailable(RuntimeError):
    pass


def _tail(path: str, root: str) -> str:
    return path[len(root):].replace("\\", "/")


def docker_argv(tool: str, args: list[str], evidence_dir: Path, network: str) -> list[str]:
    """Wrap one tool invocation as a container run.

    `args` are the argv that would have gone to the host binary, with `{out}`
    already substituted to a host path; any such path is rewritten to the mount.
    """
    image = IMAGES.get(tool)
    if image is None:
        raise IsolationUnavailable(
            f"no container image is configured for {tool}; refusing to run it "
            "unsandboxed while isolation is enabled"
        )
    if shutil.which("docker") is None:
        raise IsolationUnavailable("docker is not on PATH but REDFOX_ISOLATE=docker")

    root = str(Path(evidence_dir).resolve())
    mapped = []
    for arg in args:
        text = str(arg)
        flag, sep, value = text.partition("=")
        if sep and value.startswith(root):
            text = f"{flag}={EVIDENCE_MOUNT}{_tail(value, root)}"
        elif text.startswith(root):
            text = EVIDENCE_MOUNT + _tail(text, root)
        mapped.append(text)

    volumes = [f"{root}:{EVIDENCE_MOUNT}"]
    if tool in VOLUMES:
        volumes.append(":".join(VOLUMES[tool]))

    args_out = [
        "docker", "run", "--rm",
        "--network", network or "bridge",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "512",
    ]
    for volume in volumes:
        args_out += ["-v", volume]
    return args_out + ["-w", EVIDENCE_MOUNT, image, *mapped]