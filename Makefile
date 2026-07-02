.PHONY: build check clean fmt install lint pam test test-pam vet

GOEXPERIMENT = runtimesecret
BINDIR = build
PREFIX = /usr/local
PAM_DIR = contrib/pam/kpxcd-pam

LDFLAGS = -s -w
GOFLAGS = -trimpath

build: $(BINDIR)/kpxcd $(BINDIR)/kpxcctl

$(BINDIR)/kpxcd: $(wildcard cmd/kpxcd/*.go internal/**/*.go go.mod go.sum)
	@mkdir -p $(BINDIR)
	GOEXPERIMENT=$(GOEXPERIMENT) go build -o $@ $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/kpxcd

$(BINDIR)/kpxcctl: $(wildcard cmd/kpxcctl/*.go internal/**/*.go go.mod go.sum)
	@mkdir -p $(BINDIR)
	GOEXPERIMENT=$(GOEXPERIMENT) go build -o $@ $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/kpxcctl

install: build
	install -Dm755 $(BINDIR)/kpxcd $(DESTDIR)$(PREFIX)/bin/kpxcd
	install -Dm755 $(BINDIR)/kpxcctl $(DESTDIR)$(PREFIX)/bin/kpxcctl
	install -Dm644 contrib/systemd/kpxcd.service \
		$(DESTDIR)/usr/lib/systemd/user/kpxcd.service
	install -Dm644 contrib/systemd/kpxcd.socket \
		$(DESTDIR)/usr/lib/systemd/user/kpxcd.socket
	# Patch the service file so ExecStart matches the installation prefix.
	sed -i 's|/usr/local/bin|$(PREFIX)/bin|' \
		$(DESTDIR)/usr/lib/systemd/user/kpxcd.service
	install -Dm600 contrib/kpxcd.toml.example \
		$(DESTDIR)/etc/kpxcd/kpxcd.toml.example
	install -Dm644 contrib/polkit/org.keepassxc.daemon.policy \
		$(DESTDIR)/usr/share/polkit-1/actions/org.keepassxc.daemon.policy
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -d $(DESTDIR)$(PREFIX)/share/man/man5
	install -d $(DESTDIR)$(PREFIX)/share/man/man8
	install -Dm644 contrib/man/kpxcctl.1 $(DESTDIR)$(PREFIX)/share/man/man1/kpxcctl.1
	install -Dm644 contrib/man/kpxcd.toml.5 $(DESTDIR)$(PREFIX)/share/man/man5/kpxcd.toml.5
	install -Dm644 contrib/man/kpxcd.8 $(DESTDIR)$(PREFIX)/share/man/man8/kpxcd.8
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	install -d $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	install -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	install -Dm644 contrib/completion/kpxcctl.bash $(DESTDIR)$(PREFIX)/share/bash-completion/completions/kpxcctl
	install -Dm644 contrib/completion/kpxcctl.fish $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/kpxcctl.fish
	install -Dm644 contrib/completion/kpxcctl.zsh $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_kpxcctl

pam:
	cd $(PAM_DIR) && cargo build --release

test:
	GOEXPERIMENT=$(GOEXPERIMENT) go test ./...

test-pam:
	cd $(PAM_DIR) && cargo fmt -- --check
	cd $(PAM_DIR) && cargo test

fmt:
	gofmt -w $$(find cmd internal -name '*.go')
	cd $(PAM_DIR) && cargo fmt

vet:
	GOEXPERIMENT=$(GOEXPERIMENT) go vet ./...

check: fmt vet test test-pam

lint:
	golangci-lint run

clean:
	rm -rf $(BINDIR)/ $(PAM_DIR)/target/
