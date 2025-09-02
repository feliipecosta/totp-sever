# --- Build Stage ---
# Official Go image as the builder.
FROM golang:1.25-alpine AS builder

# Set the working directory inside the container.
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies first.
# This leverages Docker's layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code.
COPY . .

# Build the Go application.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /totp-server ./main.go


FROM gcr.io/distroless/static-debian11

# Set the working directory.
WORKDIR /app

# Copy the compiled binary from the builder stage.
COPY --from=builder /totp-server .

# Copy the templates and the encrypted secrets file.
# The container only needs the encrypted file.
COPY templates/ ./templates/
COPY secrets.enc .

# Expose the port the application will run on.
EXPOSE 3450

# Set the non-root user. distroless images run as non-root by default.
USER nonroot:nonroot

# The command to run the application.
ENTRYPOINT ["/app/totp-server"]