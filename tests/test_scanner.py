from __future__ import annotations

import unittest

from main import analyze, calculate_risk
from scanner import exporters


def container_fixture(**overrides):
    container = {
        "Config": {"Image": "alpine:3.20", "User": "", "Env": []},
        "HostConfig": {
            "Binds": None,
            "ReadonlyRootfs": False,
            "Privileged": False,
            "CapAdd": None,
            "CapDrop": None,
            "SecurityOpt": None,
            "PidMode": "",
            "IpcMode": "",
            "NetworkMode": "bridge",
        },
        "NetworkSettings": {"Ports": {}},
        "Mounts": [],
    }
    for key, value in overrides.items():
        container[key] = value
    return container


class ScannerScoringTests(unittest.TestCase):
    def test_default_container_is_not_automatically_high(self):
        result = analyze(container_fixture())
        self.assertEqual(result["risk"], "LOW")
        self.assertLess(result["score"], 35)

    def test_latest_default_container_is_medium(self):
        container = container_fixture(Config={"Image": "alpine:latest", "User": "", "Env": []})
        result = analyze(container)
        self.assertEqual(result["risk"], "MEDIUM")

    def test_docker_socket_is_critical(self):
        container = container_fixture(
            HostConfig={
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PidMode": "",
                "IpcMode": "",
                "NetworkMode": "bridge",
            },
            Mounts=[{
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
                "Type": "bind",
            }],
        )
        result = analyze(container)
        self.assertEqual(result["risk"], "CRITICAL")

    def test_unconfined_seccomp_is_reported(self):
        container = container_fixture(
            HostConfig={
                "Binds": None,
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined"],
                "PidMode": "",
                "IpcMode": "",
                "NetworkMode": "bridge",
            },
        )
        result = analyze(container)
        self.assertIn("HIGH: Seccomp is explicitly disabled", result["issues"])

    def test_single_high_maps_to_medium(self):
        self.assertEqual(calculate_risk([{"severity": "HIGH"}]), "MEDIUM")


class ExporterTests(unittest.TestCase):
    def test_sarif_contains_results(self):
        report = {
            "containers": [{
                "id": "abc123",
                "image": "alpine",
                "findings": [{
                    "id": "test_finding",
                    "title": "Test finding",
                    "severity": "HIGH",
                    "category": "runtime",
                    "evidence": "fixture",
                    "impact": "impact",
                    "recommendation": "fix",
                    "cis": "",
                }],
            }],
            "project_files": {"findings": []},
        }
        sarif = exporters.to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
