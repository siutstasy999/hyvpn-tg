import os
import subprocess
import sys

import pytest


def test_render_hysteria_config(tmp_path):
    template = tmp_path / "in.yaml"
    output = tmp_path / "out.yaml"
    template.write_text(
        "a: ${ACME_DOMAIN}\nb: ${ACME_EMAIL}\nc: ${TRAFFIC_STATS_SECRET}\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(
        ACME_DOMAIN="vpn.example.com",
        ACME_EMAIL="admin@example.com",
        TRAFFIC_STATS_SECRET="secret-value",
    )
    subprocess.run(
        [
            sys.executable,
            "bin/render_hysteria_config.py",
            str(template),
            str(output),
        ],
        check=True,
        env=env,
    )
    assert output.read_text(encoding="utf-8") == (
        "a: vpn.example.com\nb: admin@example.com\nc: secret-value\n"
    )
    if sys.platform == "win32":
        pytest.skip("POSIX file modes are not enforced on NTFS")
    assert output.stat().st_mode & 0o777 == 0o600
