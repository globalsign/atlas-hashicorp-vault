set -e
echo "== Starting Tests"
t="/tmp/go-cover.$$.tmp"
go test -coverprofile=$t $@
echo "== Finished Test"