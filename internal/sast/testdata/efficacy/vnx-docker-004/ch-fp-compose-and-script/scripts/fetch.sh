#!/bin/sh
# ADD https://example.com/file is what the old Dockerfile did
echo "ADD https://dl.example.com/a.tgz /tmp/" >> Dockerfile.generated
