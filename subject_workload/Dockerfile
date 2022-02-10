FROM golang:alpine

# Set environmet variables
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

LABEL "type"="subjectwl"

# Create and move to working directory
RUN mkdir /build
WORKDIR /build

# Copy the code
COPY . .

# Copy and download dependency
RUN go mod download

# Build the application
RUN go build -o main .

# Export necessary port
EXPOSE 8080

# Command to run when starting the container
CMD ["/build/main"]
