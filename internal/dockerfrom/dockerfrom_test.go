package dockerfrom

import (
	"strings"
	"testing"
)

const multiStage = `# syntax=docker/dockerfile:1
ARG NODE=20.11.1
ARG ALPINE

FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git=1:2.39.5-0+deb12u1 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

FROM build AS test
RUN go test ./...

FROM node:${NODE}-alpine3.19
ARG EXTRA=tini
RUN apk add --no-cache curl=8.5.0-r0 $EXTRA python3
RUN npm ci --omit=dev
COPY --from=build /out /app

FROM node:${NODE}-alpine${ALPINE} AS never
`

func TestParseMultiStage(t *testing.T) {
	st := Parse(strings.NewReader(multiStage))
	if len(st) != 4 {
		t.Fatalf("%d stages", len(st))
	}
	build, test, final, never := st[0], st[1], st[2], st[3]
	if build.Name != "build" || build.ResolvedRef != "golang:1.22-bookworm" || build.Line != 5 || build.Platform != "$BUILDPLATFORM" {
		t.Errorf("build: %+v", build)
	}
	if len(build.Installs) != 1 || build.Installs[0].Manager != "apt" || build.Installs[0].Line != 6 {
		t.Fatalf("build installs: %+v", build.Installs)
	}
	pk := build.Installs[0].Packages
	if len(pk) != 2 || pk[0].Name != "git" || pk[0].Spec != "git=1:2.39.5-0+deb12u1" || pk[1].Name != "ca-certificates" {
		t.Errorf("apt packages across continuations: %+v", pk)
	}
	if test.FromStage != "build" || test.ResolvedRef != "" {
		t.Errorf("a stage from a stage: %+v", test)
	}
	if final.ResolvedRef != "node:20.11.1-alpine3.19" || final.IsFinal || final.Line != 14 {
		t.Errorf("ARG default applied: %+v", final)
	}
	ap := final.Installs[0].Packages
	if final.Installs[0].Manager != "apk" || len(ap) != 3 || ap[0].Spec != "curl=8.5.0-r0" || ap[1].Name != "tini" || ap[2].Name != "python3" {
		t.Errorf("apk packages with a stage ARG: %+v", ap)
	}
	if !never.IsFinal || !never.UnresolvedArgs || never.ResolvedRef != "" {
		t.Errorf("an ARG without a default is unresolved, and the last stage is final: %+v", never)
	}
}

func TestParseInstallsPerManager(t *testing.T) {
	for run, want := range map[string]string{
		"dnf install -y --setopt=tsflags=nodocs openssl-libs-3.0.7 && dnf clean all": "dnf:openssl-libs-3.0.7",
		"microdnf install -y shadow-utils":                                           "microdnf:shadow-utils",
		"yum -y install httpd":                                                       "yum:httpd",
		"pacman -Syu --noconfirm curl=8.10.1-2":                                      "pacman:curl",
		"zypper --non-interactive in -y curl":                                        "zypper:curl",
		"DEBIAN_FRONTEND=noninteractive apt install -y -t bookworm-backports curl":   "apt:curl",
		"sudo apk add tini":                                                          "apk:tini",
		"/sbin/apk add --virtual .build gcc":                                         "apk:gcc",
		"echo 'apk add nothing'":                                                     "",
		"apt-get update":                                                             "",
	} {
		ins := parseInstalls(1, run)
		got := ""
		if len(ins) > 0 {
			var names []string
			for _, p := range ins[0].Packages {
				names = append(names, p.Name)
			}
			got = ins[0].Manager + ":" + strings.Join(names, " ")
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", run, got, want)
		}
	}
}

func TestScratchAndComments(t *testing.T) {
	st := Parse(strings.NewReader("FROM scratch\n# FROM ignored:1\nCOPY app /app\n"))
	if len(st) != 1 || st[0].ResolvedRef != "" || !st[0].IsFinal {
		t.Fatalf("scratch: %+v", st)
	}
	if len(Parse(strings.NewReader("# nothing here\n"))) != 0 {
		t.Fatal("a file with no FROM has no stages")
	}
}

func TestASourceFileNamedLikeADockerfileDeclaresNothing(t *testing.T) {
	goSource := "package containercuration\n\n// DockerfileInput is what a migration's Dockerfile is rendered from.\ntype DockerfileInput struct {\n\tFrom    string\n}\n"
	if got := Parse(strings.NewReader(goSource)); got != nil {
		t.Fatalf("dockerfile.go is not a Dockerfile: %+v", got)
	}
	if got := Parse(strings.NewReader("ENV A=1\nFROM alpine:3.20\n")); got != nil {
		t.Fatalf("only ARG may precede FROM: %+v", got)
	}
	if got := Parse(strings.NewReader("# syntax=docker/dockerfile:1\nARG V=3.20\nFROM alpine:${V}\n")); len(got) != 1 || got[0].ResolvedRef != "alpine:3.20" {
		t.Fatalf("a directive and ARG before FROM is a Dockerfile: %+v", got)
	}
}
