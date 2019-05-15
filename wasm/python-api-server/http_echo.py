#!/usr/bin/env python

from flask import Flask, jsonify, request, Response
from functools import wraps
from optparse import OptionParser
from werkzeug.routing import Rule
from wasmer import Instance, validate, Value
import json
import pprint
import time


app = Flask(__name__)
policy = None


def eval(input):
    """Invoke the compiled policies eval function with a given input"""
    input_length = len(input)

    # using the loaded wasm policy, check if
    # this request is allowed or not
    global policy
    
    # Allocate memory for the input string
    addr = policy.export.opa_malloc(input_length)

    # Get a "view" of the address as a uint8 array
    memory = policy.memory.uint8_view(addr)

    # Copy the input string into the memory
    for i in range(input_length):
        memory[i] = input[i]

    return policy.exports.eval(addr, input_length)


def check_policy(func):
    """Decorator to enforce policy on API calls"""
    @wraps(func)
    def decorated_function(*args, **kwargs):

        # Evaluate the policy and respond accordingly
        allowed = eval(json.dumps(request))
        
        if not allowed:
            response = jsonify({"error": "Not allowed by policy"})
            response.status_code = "403"
            response.status = "Forbidden"
            return response
        else:
            return func(*args, **kwargs)

    return decorated_function


def _extract(d):
    """Helper to build response dicts"""
    return {key: value for (key, value) in d.items()}


# Route all calls to "echo"
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
@check_policy
def echo(path):
    """Responds with details about the request recieved."""
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
    # Read the file (could be fetched remotely or something too)
    wasm_bytes = open(policy_file, 'rb').read()

    # Use the wasmer validate API to ensure the file was legit
    if not validate(wasm_bytes):
        print('The program seems corrupted.')
        exit(1)

    # Create a new instance (load the wasm program and initialize the runtime)
    instance = Instance(wasm_bytes)
    return instance

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
