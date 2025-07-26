FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    gdb \
    lldb \
    git \
    pkg-config \
    man \
    xxd \
    nasm \
    valgrind \
    && rm -rf /var/lib/apt/lists/*
