***Note: This is currently blocked by https://github.com/wasmerio/python-ext-wasm/issues/28 ***

# Python API Server w/ WASM Rego Policy

This example shows how to use [wasmer](https://github.com/wasmerio/wasmer) to load and run compiled
Rego policies in python applications.

## Building

Everything gets built in a docker image

```bash
docker build -t http-echo .
```

Dependencies will be installed, policy will be compiled, and everything
ready to run in the image.

> See the [Dockerfile](./Dockerfile) for details on each step!

## Running

The image has the entry point set to `/bin/http-echo` which will start the
[http_echo.py](./http_echo.py) service.

Start the container with something like:

```bash
docker run --rm -it -p 8080:8080 http-echo
```

Then send requests to it

```bash
curl -s http://localhost:8080/
```
