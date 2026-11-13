"""Transport adapters that expose the two service entry points uniformly.

* :func:`make_wsgi_driver` drives the Werkzeug-based
  :class:`~certomancer.integrations.animator.Animator` through its in-process
  test client (the same path used by ``tests/test_animator.py``).
* :func:`make_aiohttp_driver` invokes the aiohttp route handler directly with
  a mocked request, so no TCP socket has to be bound (the CI sandbox forbids
  local port binding).

Both return :class:`~tests.structure_fuzz.engine.AdapterResult`, letting the
fuzz engine treat them identically.
"""

import asyncio
from datetime import datetime, timezone
from typing import Callable

from aiohttp.test_utils import make_mocked_request
from aiohttp.streams import StreamReader
from werkzeug.test import Client
from werkzeug.wrappers import Response

from certomancer.integrations._animator_shared import FAKE_TIME_HEADER
from certomancer.integrations.animator import (
    Animator,
    AnimatorArchStore,
)
from certomancer.integrations.aiohttp_animator import build_animator_app
from certomancer.registry import ArchLabel, ServiceLabel

from .engine import AdapterResult

FIXED_TIME = datetime(2020, 11, 1, tzinfo=timezone.utc)
FIXED_TIME_HEADER = '2020-11-01T00:00:00+0000'


def _route_handler(app, path_template: str):
    for route in app.router.routes():
        resource = route.resource
        if resource is not None and resource.canonical == path_template:
            return route.handler
    raise LookupError(f'no route for {path_template}')


def make_wsgi_driver(
    architectures,
    arch: ArchLabel,
    service: str,
    label: ServiceLabel,
) -> Callable[[bytes], AdapterResult]:
    animator = Animator(
        AnimatorArchStore(architectures),
        at_time=FIXED_TIME,
        with_web_ui=False,
    )
    client = Client(animator, Response)
    path = f'/{arch}/{service}/{label}'

    def driver(der: bytes) -> AdapterResult:
        try:
            response = client.post(
                path,
                data=der,
                headers={FAKE_TIME_HEADER: FIXED_TIME_HEADER},
            )
        except Exception as exc:  # framework surfaced an exception directly
            return AdapterResult(http_status=0, body=None, exc=exc)
        return AdapterResult(
            http_status=response.status_code,
            body=response.data,
            exc=None,
        )

    return driver


def make_aiohttp_driver(
    architectures,
    arch: ArchLabel,
    service: str,
    label: ServiceLabel,
) -> Callable[[bytes], AdapterResult]:
    app = build_animator_app(architectures, with_web_ui=False)
    template = (
        '/{arch}/ocsp/{label}'
        if service == 'ocsp'
        else '/{arch}/tsa/{label}'
    )
    handler = _route_handler(app, template)
    path = f'/{arch}/{service}/{label}'
    content_type = (
        'application/ocsp-request'
        if service == 'ocsp'
        else 'application/timestamp-query'
    )

    def driver(der: bytes) -> AdapterResult:
        async def invoke() -> AdapterResult:
            reader = StreamReader(
                make_mocked_request('POST', '/')._protocol,
                2 ** 20,
                loop=asyncio.get_running_loop(),
            )
            reader.feed_data(der)
            reader.feed_eof()
            mock_req = make_mocked_request(
                'POST',
                path,
                headers={
                    'Content-Type': content_type,
                    FAKE_TIME_HEADER: FIXED_TIME_HEADER,
                },
                match_info={'arch': str(arch), 'label': str(label)},
                app=app,
                payload=reader,
            )
            try:
                web_response = await handler(mock_req)
                body = web_response.body
                return AdapterResult(
                    http_status=web_response.status,
                    body=body,
                    exc=None,
                )
            except Exception as exc:  # includes web.HTTPException subclasses
                status = getattr(exc, 'status_code', 0)
                body = getattr(exc, 'body', None)
                return AdapterResult(
                    http_status=status or 500,
                    body=body if isinstance(body, bytes) else None,
                    exc=exc,
                )

        return asyncio.run(invoke())

    return driver


def make_faulty_wsgi_driver(
    architectures,
    arch: ArchLabel,
    service: str,
    label: ServiceLabel,
    faulty_responder_factory,
    faulty_timestamper_factory,
) -> Callable[[bytes], AdapterResult]:
    """WSGI driver whose summoned signing service is replaced by a faulty one.

    The faulty objects are instantiated once and reused for every request so
    the negative test exercises exactly the injected misimplementation.
    """
    animator = Animator(
        AnimatorArchStore(architectures),
        at_time=FIXED_TIME,
        with_web_ui=False,
    )
    pki_arch = animator.architectures[arch]
    registry = pki_arch.service_registry
    path = f'/{arch}/{service}/{label}'

    if service == 'ocsp':
        responder = faulty_responder_factory(
            pki_arch, label, FIXED_TIME
        )

        def summon_responder(_label, _at_time=None):
            return responder

        registry.summon_responder = summon_responder  # type: ignore[assignment]
    else:
        timestamper = faulty_timestamper_factory(
            pki_arch, label, FIXED_TIME
        )

        def summon_timestamper(_label, _at_time=None):
            return timestamper

        registry.summon_timestamper = (  # type: ignore[assignment]
            summon_timestamper
        )

    client = Client(animator, Response)

    def driver(der: bytes) -> AdapterResult:
        try:
            response = client.post(
                path,
                data=der,
                headers={FAKE_TIME_HEADER: FIXED_TIME_HEADER},
            )
        except Exception as exc:
            return AdapterResult(http_status=0, body=None, exc=exc)
        return AdapterResult(
            http_status=response.status_code,
            body=response.data,
            exc=None,
        )

    return driver
