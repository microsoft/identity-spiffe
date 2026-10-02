"""Private HTTP worker. Payloads travel over a pipe, never stdout or log files."""
from http.client import HTTPException
import json
from urllib import error, request as urllib_request


class NetworkFailure(Exception):
    """Only fixed diagnostics cross the transport boundary."""


class NoRedirect(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NetworkFailure("redirect")


def exchange(method, url, headers, body=None, timeout=20):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib_request.Request(url, data=data, headers=headers, method=method)
    opener = urllib_request.build_opener(urllib_request.ProxyHandler({}), NoRedirect())
    try:
        try:
            response = opener.open(req, timeout=timeout)
        except error.HTTPError as exc:
            response = exc
        with response:
            status = response.code
            raw = response.read(1_048_577)
        if 300 <= status < 400:
            raise NetworkFailure("redirect")
        if len(raw) > 1_048_576:
            raise NetworkFailure("oversize")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise NetworkFailure("invalid_json") from None
        if not isinstance(value, dict):
            raise NetworkFailure("invalid_shape")
        return status, value
    except (error.URLError, OSError, ValueError, HTTPException):
        raise NetworkFailure("request_failed") from None


def worker(connection, payload):
    try:
        try:
            result = exchange(*payload)
        except NetworkFailure:
            result = (None, None)
        connection.send(result)
    except (BrokenPipeError, EOFError, OSError):
        # Parent timed out and discarded this worker; no result is a failure.
        pass
    finally:
        connection.close()
