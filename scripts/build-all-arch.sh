#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

mkdir -p release
while read p; do
  OS=`echo "$p" | cut -f1`
  ARCH=`echo "$p" | cut -f2`

  echo "Building ${OS} ${ARCH} Binary"

  GOOS=$OS GOARCH="$GOARCH" go build -o "release/atlas-$OS-$ARCH" cmd/atlas/main.go
done <<EOF
darwin	386
darwin	amd64
darwin	arm
darwin	arm64
freebsd	386
freebsd	amd64
freebsd	arm
linux	386
linux	amd64
linux	arm
linux	arm64
linux	ppc64
linux	ppc64le
linux	mips
linux	mipsle
linux	mips64
linux	mips64le
netbsd	386
netbsd	amd64
netbsd	arm
openbsd	386
openbsd	amd64
openbsd	arm
solaris	amd64
windows	386
windows	amd64
EOF
