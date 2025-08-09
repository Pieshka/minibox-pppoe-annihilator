#!/bin/sh

cd buildroot

# Rebuild webapi
make webapi-dirclean
make webapi-rebuild

# Install in final image
make
