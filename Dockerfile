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

# expose ports that are default for a bootstrap node
EXPOSE 443/tcp 3389/tcp 33445/tcp 33445/udp

# add user
RUN useradd tox_node

# change running user
USER tox_node

ENTRYPOINT ["/user/local/tox-node"]
CMD []
