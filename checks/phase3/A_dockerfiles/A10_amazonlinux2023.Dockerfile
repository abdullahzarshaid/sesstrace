FROM docker.io/library/amazonlinux:2023
RUN dnf install -y python3.12 && dnf clean all
