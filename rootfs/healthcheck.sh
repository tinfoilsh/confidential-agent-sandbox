#!/bin/bash
set -euo pipefail
exec timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22 || exec 3<>/dev/tcp/127.0.0.1/8080'
