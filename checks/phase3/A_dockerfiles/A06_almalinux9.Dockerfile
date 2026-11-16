FROM docker.io/library/almalinux:9
RUN dnf install -y python3.12 && dnf clean all
