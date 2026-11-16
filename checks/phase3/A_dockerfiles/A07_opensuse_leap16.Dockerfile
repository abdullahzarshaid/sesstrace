FROM docker.io/opensuse/leap:16.0
RUN zypper --non-interactive install python3 && zypper clean --all
