
### Example for creating gitlab runner
```sh
set version=1.21.0
set os=linux
set target=$os-rust-$version
gitlab-runner register -n --name $target --url https://gitlab.com/ --registration-token <token> --tag-list rust,rust-$version,$version --run-untagged=true --executor docker --docker-image rust:$version --docker-hostname build.tox
```
