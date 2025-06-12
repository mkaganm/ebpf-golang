@echo off
echo Building and running the eBPF Security Monitor...

echo Building Docker image...
docker compose build

echo Starting security monitor...
docker compose up

echo Done!
