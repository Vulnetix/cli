FROM golang:1.22-bookworm
~>ADD https://github.com/example/plugins.git#main /src/plugins
~>ADD git@github.com:example/private-lib.git /src/private-lib
~>ADD ["https://example.com/config/app.yaml", "/etc/app/app.yaml"]
~>ADD --link \
    https://storage.example.com/models/classifier-v3.onnx \
    /models/classifier.onnx
~>ONBUILD ADD https://example.com/onbuild/hooks.sh /hooks.sh
