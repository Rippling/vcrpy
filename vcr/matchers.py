import json
from six.moves import urllib, xmlrpc_client
from .util import read_body
import logging
import re
from base64 import b64decode

log = logging.getLogger(__name__)


def method(r1, r2):
    return r1.method == r2.method

# uri = host + path + stringified(query)
# To make query order-independent, comparing only host and path here
def uri(r1, r2):
    return host(r1, r2) and path(r1, r2)


def host(r1, r2):
    return r1.host == r2.host


def scheme(r1, r2):
    return r1.scheme == r2.scheme


def port(r1, r2):
    return r1.port == r2.port


def path(r1, r2):
    return r1.path == r2.path


def query(r1, r2):
    return frozenset(r1.query) == frozenset(r2.query)


def raw_body(r1, r2):
    return read_body(r1) == read_body(r2)


def _header_checker(value, header='Content-Type'):
    def checker(headers):
        return value in headers.get(header, '').lower()
    return checker

def _sort_dict_values(dict):
    sorted_dict = dict.copy()
    keys = list(dict.keys())
    for key in keys:
        values = dict[key]
        if isinstance(values, list):
            sorted_dict[key] = sorted(values)
    return sorted_dict

def _transform_json(body):
    # Request body is always a byte string, but json.loads() wants a text
    # string. RFC 7159 says the default encoding is UTF-8 (although UTF-16
    # and UTF-32 are also allowed: hmmmmm).
    if body:
        return json.loads(body.decode('utf-8'), object_hook = lambda dict: _sort_dict_values(dict))


def _transform_multipart_form_data(body):
    hardcoded_boundary = "--ad8bdc022fa24a86a8a45730c69df640"
    if body:
        if isinstance(body, bytes):
            body = body.decode()
        boundary = body.split("\r\n")[0]
        return body.replace(boundary, hardcoded_boundary)
    return body


_xml_header_checker = _header_checker('text/xml')
_xmlrpc_header_checker = _header_checker('xmlrpc', header='User-Agent')
_checker_transformer_pairs = (
    (_header_checker('multipart/form-data'), _transform_multipart_form_data),
    (_header_checker('application/x-www-form-urlencoded'), urllib.parse.parse_qs),
    (_header_checker('application/json'), _transform_json),
    (lambda request: _xml_header_checker(request) and _xmlrpc_header_checker(request), xmlrpc_client.loads),
)


def _identity(x):
    return x


def _get_transformer(request):
    for checker, transformer in _checker_transformer_pairs:
        if checker(request.headers):
            return transformer
    else:
        return _identity


def body(r1, r2):
    transformer = _get_transformer(r1)
    r2_transformer = _get_transformer(r2)
    if transformer != r2_transformer:
        transformer = _identity
    return transformer(read_body(r1)) == transformer(read_body(r2))

def _is_jwt_token(auth_token):
    # "ey" as prefix ensures that the first character is a `{`, which is found only in case
    # of JWT tokens
    token_match = re.search(r'^(Bearer|token)\ ey[a-zA-Z0-9]{3,}\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+', auth_token)
    return True if token_match else False

def _check_authorization(headers):
    auth_token = headers['Authorization']
    if _is_jwt_token(auth_token):
        payload = auth_token.split(".")[1]
        payload += '=' * (-len(payload) % 4) # Ignore 'Incorrect padding' error when base64 decoding
        payload_dict = json.loads(b64decode(payload))
        return payload_dict
    else:
        return auth_token

def _headers_without_authorization(headers):
    new_headers = headers.copy()
    new_headers.pop('Authorization')
    return new_headers

def headers(r1, r2):
    r1_headers = r1.headers
    r2_headers = r2.headers
    if 'Authorization' in list(r1_headers.keys()) and 'Authorization' in list(r2_headers.keys()):
        return _headers_without_authorization(r1_headers) == _headers_without_authorization(r2_headers) and _check_authorization(r1_headers) == _check_authorization(r2_headers)
    else:
        return r1_headers == r2_headers


def _log_matches(r1, r2, matches):
    differences = [m for m in matches if not m[0]]
    if differences:
        log.debug(
            "Requests {0} and {1} differ according to "
            "the following matchers: {2}".format(r1, r2, differences)
        )

def requests_match(r1, r2, matchers):
    matches = [(m(r1, r2), m) for m in matchers]
    _log_matches(r1, r2, matches)
    return all([m[0] for m in matches])
