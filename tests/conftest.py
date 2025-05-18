from dataclasses import dataclass
import os
from pathlib import Path
import pytest
import subprocess


@dataclass
class GlobalConfig:
    samples = os.path.abspath("samples")
    logs = os.path.abspath("logs")
    scripts = os.path.abspath("scripts")
    ida = "ida"


global_config = GlobalConfig()


def cleanup_samples():
    """
    Remove all files in the samples directory.
    """
    ext = {".i64", ".id0", ".id1", ".id2", ".til", ".nam"}
    samples_dir = Path(global_config.samples)
    for file in samples_dir.iterdir():
        if file.is_file():
            if file.suffix.lower() in ext:
                file.unlink()


def pytest_addoption(parser):
    parser.addoption("--ida", action="store", default="ida")


def pytest_configure(config):
    global_config.ida = config.getoption("ida")


def pytest_unconfigure(*_):
    cleanup_samples()


@pytest.fixture(autouse=False)
def samples():
    return global_config.samples


@pytest.fixture(autouse=False)
def logs():
    return global_config.logs


@pytest.fixture(autouse=False)
def scripts():
    return global_config.scripts


@pytest.fixture(autouse=False)
def ida():
    return global_config.ida


@pytest.fixture(autouse=False)
def run_ida(ida, scripts, samples, logs):
    def _run(
            script,
            sample,
            output=None,
            discard=True,     # discard any existing DB
            autonomous=True,  # autonomous mode
            extra_ida_args=None,
            extra_plugin_args=None,
    ):
        if extra_ida_args is None:
            extra_ida_args = []
        if extra_plugin_args is None:
            extra_plugin_args = []

        script = f"{scripts}/{script}"
        sample = f"{samples}/{sample}"
        output = f"{logs}/{output}" if output else ''

        cmd = [ida]
        if discard:
            cmd.append("-c")
        if autonomous:
            cmd.append("-A")
        cmd.extend([
            f"-S{script} {output} {' '.join(extra_plugin_args)}",
            sample,
            *extra_ida_args
        ])

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc.returncode

    return _run
