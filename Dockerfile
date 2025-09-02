# --- Build Stage ---
# Use an official Go image as the builder.
# Specify the Go version to ensure reproducibility.
FROM golang:1.21-alpine AS builder

# Set the working directory inside the container.
WORKDIR /app

# Copy go.mod and go.sum files to download dependencies first.
# This leverages Docker's layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code.
COPY . .

# Build the Go application.
# CGO_ENABLED=0 is crucial for creating a static binary that works in distroless.
# -ldflags "-s -w" strips debugging information, making the binary smaller.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o /2fa-server ./main.go


# --- Final Stage ---
# Use a distroless static image as the final base image.
# It contains only our application and its runtime dependencies, nothing else.
FROM gcr.io/distroless/static-debian11

# Set the working directory.
WORKDIR /app

# Copy the compiled binary from the builder stage.
COPY --from=builder /2fa-server .

# Copy the templates and the encrypted secrets file.
# The container only needs the encrypted file.
COPY templates/ ./templates/
COPY secrets.enc .

# Expose the port the application will run on.
EXPOSE 3450

# Set the non-root user. distroless images run as non-root by default.
USER nonroot:nonroot

# The command to run the application.
ENTRYPOINT ["/app/2fa-server"]