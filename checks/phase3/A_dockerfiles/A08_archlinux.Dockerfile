FROM docker.io/library/archlinux:base-20261108.0.623074
RUN pacman -Syu --noconfirm python && pacman -Scc --noconfirm
