# Docker based development environment

Reference docker containers with all dependencies needed to develop ebpfguard.

This instruction assumes that docker is installed. For convenience you can add your user to docker group.
The following script checks whether current user is in docker group.

``` bash
$ groups | grep docker 1>/dev/null 2>&1 || echo "$USER is not in docker group. docker command will require sudo"
```

## Ubuntu

To build ubuntu based development docker image run the following `docker build` command.

```bash
$ pwd
<path to ebpfguard repo>/docker
$ cd ubuntu
$ docker build . -t ebpfguard-dev:local
```

After building you can start a container with this repository mounted into it and run compilation steps. Proposed `docker run` invocation doesn't copy repository contents. Changes made within container will be present on host machine.

```bash
# privileged flag is needed to run ebpfguard applications from within container
$ docker run -it --privileged -v <path to this repository on local filesystem>:/app ebpfguard-dev:local bash
# Previous command drops user into bash shell within container
$ cd app
$ cargo xtask build-ebpf && cargo build && cargo test
```

Lets assume that ebpfguard repository was cloned to `/home/user/ebpfguard`.

Docker run command would be:
```bash
$ docker run -it --privileged -v /home/user/ebpfguard:/app ebpfguard-dev:local bash
```
