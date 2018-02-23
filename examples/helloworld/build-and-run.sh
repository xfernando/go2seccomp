#!/bin/bash
cd "$(dirname "$0")"

echo -e "\e[1mBuilding helloworld binary...\e[0m"
env GOOS=linux GOARCH=amd64 go build -v
echo -e "\e[1mGenerating seccomp profile from helloworld binary:\e[0m"
go2seccomp helloworld profile.json
echo -e "\e[1mBuilding helloworld docker image:\e[0m"
docker build -t helloworld .
echo -e "\e[1mRunning the container:\e[0m"
docker run --rm --security-opt="no-new-privileges" --security-opt="seccomp=profile.json" helloworld