# CIS Docker Benchmark InSpec Profile

```sh
docker run -it --rm -v $(pwd):/share chef/inspec:latest exec -t ssh://user@host -i <private_key> --sudo
```