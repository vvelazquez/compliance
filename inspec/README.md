#  Docker EE (Standard/Advanced) InSpec Profiles

From the root of the inspec directory, the profiles below can be executed.

## FedRAMP

```sh
# Build Dockerfile
docker build -t docker/compliance-inspec-fedramp:latest .

# Moderate baseline
docker run -it --rm -v <path_to_private_key>:/share/private_key docker/compliance-inspec-fedramp:latest exec Moderate -t ssh://user@host -i /share/private_key --sudo

# High baseline
docker run -it --rm -v <path_to_private_key>:/share/private_key docker/compliance-inspec-fedramp:latest exec High -t ssh://user@host -i /share/private_key --sudo
```
