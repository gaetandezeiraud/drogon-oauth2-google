# Stage 1: Build
FROM ubuntu:24.04 AS builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV VCPKG_ROOT=/opt/vcpkg

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    libssl-dev \
    ninja-build

# Install vcpkg
RUN git clone https://github.com/microsoft/vcpkg.git $VCPKG_ROOT && \
    $VCPKG_ROOT/bootstrap-vcpkg.sh

# Install Drogon using vcpkg
# RUN $VCPKG_ROOT/vcpkg install drogon

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Build the project
RUN cmake --preset release && \ 
    cmake --build build-release

# Stage 2: Runtime
FROM ubuntu:24.04

# Set environment variables
# ENV VCPKG_ROOT=/opt/vcpkg

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
    libjsoncpp-dev \
    uuid-dev \
    openssl \
    libssl-dev \
    zlib1g-dev \
    libboost-all-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy the built application from the builder stage
COPY --from=builder /usr/src/app/build-release/my_drogon_app /usr/local/bin/my_drogon_app

WORKDIR /usr/local/bin
EXPOSE 8080

# Define the command to run the application
CMD ["/usr/local/bin/my_drogon_app"]
