# Stage 1: Build the Go binary
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Cache module downloads separately from source code changes
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath -o bootstrap .

# Stage 2: Minimal Lambda container
FROM public.ecr.aws/lambda/provided:al2023

COPY --from=builder /build/bootstrap /var/runtime/bootstrap

CMD ["bootstrap"]
