APPNAME   := iptables-checker
DIST_DIR  := ./dist
PLATFORMS := linux-386 linux-amd64 linux-arm

RELEASE   := $(shell git describe --all --always)

build:
	go generate
	go get -v -t ./...
	go test -v ./...
	go build -v


dist: $(PLATFORMS)
$(PLATFORMS):
	$(eval GOOS := $(firstword $(subst -, ,$@)))
	$(eval GOARCH := $(lastword $(subst -, ,$@)))
	mkdir -p $(DIST_DIR)
	env GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(DIST_DIR)/$(APPNAME).$(RELEASE).$@

md5: dist
	cd $(DIST_DIR) && md5sum $(APPNAME).$(RELEASE).* | tee MD5SUM

release: md5
	go get github.com/tcnksm/ghr
	if [ "x$$(git config --global --get github.token)" = "x" ]; then echo "Missing github.token in your git config"; fi
	ghr -recreate -u crossengage $(RELEASE) $(DIST_DIR)
