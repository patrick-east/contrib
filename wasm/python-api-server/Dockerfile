FROM openpolicyagent/opa:latest AS opa

# the opa image doesn't have a shell, so copy the binary and
# run it in another linux distro. It does require one with a
# stdlib. Can't use alpine or similar images.
FROM debian:stretch AS rego-compiler

COPY --from=opa /opa /bin/opa
COPY ./example.rego /
RUN opa build -d /example.rego -o /policy.wasm 'data.example.allow = true'

# Run in the standard python3 image
FROM python:3

# Copy the compiled WebAssembly into this image
COPY --from=rego-compiler /policy.wasm /opa/policy.wasm

# Install python requirements
COPY ./requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

# Move the python script in, rename for ease of use.
COPY ./http_echo.py /bin/http-echo

# The script defaults to port 8080
EXPOSE 8080

# Set default entrypoints (primarily to override the original python shell one)
CMD [ "http-echo" ]
ENTRYPOINT [ "http-echo" ]
