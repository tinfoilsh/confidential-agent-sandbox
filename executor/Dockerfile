FROM golang:1.26.2-alpine3.23@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
WORKDIR /src

COPY go.* ./
RUN go mod download && go mod verify

COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly -o /executor .

# BusyBox is the whole userland the agent gets: a shell and the standard
# file, text, and archive utilities in one static binary. Nothing here can
# reach a network — the container has none — so the sandbox is a place to
# think in files, not to install things.
FROM busybox:1.37.0-glibc@sha256:4279d9b47df4c1b02d80efd8d02cd59b3a8182c1e785a4ff3f6983bee19dc8b0
COPY --from=build /executor /executor
# /workspace and /tmp are mounted over by tmpfs at run time (see
# tinfoil-config.yml); the directories exist here so the mounts have
# somewhere to land. /run/execsock is a volume shared with mcp-server,
# initialized from this image — hence the ownership.
RUN mkdir -p /workspace /run/execsock /tmp \
    && chown 1000:1000 /run/execsock \
    && chmod 1777 /workspace /tmp
ENV HOME=/workspace
WORKDIR /workspace
CMD ["/executor"]
