#!/bin/bash

docker run -it --rm -v $(pwd):/app -w /app microsoft/dotnet:2.0-sdk dotnet restore && dotnet run