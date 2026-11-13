# Feedback task starting environment

Upstream: https://github.com/MatthiasValvekens/certomancer
Upstream commit: `da91cbeb39ad1b2f470e50d88d13827061f6be16`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_certs.py tests/test_services.py tests/test_utils.py -k 'not test_validate'
```

Scope note: 132 offline certificate/service/unit cases; excludes the five legacy test_validate cases whose synchronous requests_mock does not intercept the current validator aiohttp transport. Async validator integrations are outside the baseline.

Observed baseline (2026-11-13): `132 passed, 5 deselected in 13.60s`
Whole-command wall time: 13.841 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
