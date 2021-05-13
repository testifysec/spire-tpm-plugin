#!/bin/bash -e

cd "$(dirname "$0")/../"

display_usage() {
  echo -e "Usage:\n$0 [version]"
}

# check whether user had supplied -h or --help . If yes display usage
if [ $# = "--help" ] || [ $# = "-h" ]; then
  display_usage
  exit 0
fi

# check number of arguments
if [ $# -ne 1 ]; then
  display_usage
  exit 1
fi

VERSION=$1 make release
