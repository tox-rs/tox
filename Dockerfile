# build stage
FROM archlinux/base AS builder

# install build dependencies
RUN pacman --noconfirm -Sy \
    gcc \
    git \
    rust \
    diffutils \
    file \
    awk \
    make

# copy local files to container
ADD . /tox-node
WORKDIR /tox-node

# build
RUN cargo build --release

# run stage
FROM archlinux/base

COPY --from=builder /tox-node/target/release/tox-node /user/local/

# tox-node uses port of 33445 as default
EXPOSE 33445/tcp
EXPOSE 33445/udp

# add user
RUN useradd tox_node

# change running user
USER tox_node

ENTRYPOINT ["/user/local/tox-node"]
CMD []
