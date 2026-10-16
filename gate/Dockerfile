# Passkey login in front of ttyd, built and published like the claude image
# (ghcr.io/rmonk/claude-gate). To build it locally:
#
#   podman build --pull -t ghcr.io/rmonk/claude-gate:latest gate/
#
FROM docker.io/library/golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /gate . && mkdir /data

FROM gcr.io/distroless/static-debian12
COPY --from=build /gate /gate
# Passkeys and the session key; a new volume takes this owner from the image.
COPY --from=build --chown=1000:1000 /data /data
# uid 1000, like the claude user that runs ttyd, so the gate can use ttyd's socket.
USER 1000:1000
ENTRYPOINT ["/gate"]
