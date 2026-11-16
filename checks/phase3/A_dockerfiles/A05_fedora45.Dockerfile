FROM docker.io/library/fedora:45
RUN dnf install -y python3 && dnf clean all
