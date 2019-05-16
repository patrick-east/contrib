#!/usr/bin/env python

from flask import Flask, jsonify, request, Response
from functools import wraps
from optparse import OptionParser
from werkzeug.routing import Rule
import json
import pprint
import time
import opa


app = Flask(__name__)

# Global "opa.Rego" object
policy = None

# Route all calls to "echo"
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def echo(path):
    """Responds with details about the request recieved."""

    # Evaluate the policy and respond accordingly
    input_json = json.dumps(request)
    allowed = policy.eval_bool(input_json)
    if not allowed:
        response = jsonify({"error": "Not allowed by policy"})
        response.status_code = "403"
        response.status = "Forbidden"
        return response

    data = {
        'time' : time.time(),
        'path' : request.path,
        'script_root' : request.script_root,
        'url' : request.url,
        'base_url' : request.base_url,
        'url_root' : request.url_root,
        'method' : request.method,
        'headers' : _extract(request.headers),
        'data' : request.data.decode(encoding='UTF-8'),
        'host' : request.host,
        'args' : _extract(request.args),
        'form' : _extract(request.form),
        'json' : request.json,
        'cookies' : _extract(request.cookies)
    }

    response = jsonify(data)
    response.status_code = 200
    return response

def load_policy(policy_file):
    """Load the policy wasm from file and prepare for eval"""
    policy = opa.Rego(wasm_file=policy_file)
    return policy

def main():
    parser = OptionParser()
    parser.add_option('--port', dest='port', default=8080, help='port to run server on - default 8080')
    parser.add_option('--host', dest='host', default='0.0.0.0', help='host to bind server on - default 0.0.0.0')
    parser.add_option('--policy-wasm', dest='policy_wasm', default='/opa/policy.wasm', help='OPA Policy WebAssembly binary')
    parser.add_option('--debug', dest='debug',
        default=False, action='store_true', help='enable debug mode in flask')

    (options, _) = parser.parse_args()

    global policy
    policy = load_policy(options.policy_wasm)

    app.debug = options.debug
    app.run(port=int(options.port), host=options.host)

if __name__ == '__main__':
    main()
