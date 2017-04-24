#  Docker EE (Standard/Advanced) InSpec Profiles

## FedRAMP

### Moderate Baseline

```sh
docker run -it --rm -v $(pwd):/share chef/inspec:latest exec FedRAMP/Moderate -t ssh://user@host -i <private_key> --sudo
```

### High Baseline

```sh
docker run -it --rm -v $(pwd):/share chef/inspec:latest exec FedRAMP/Moderate -t ssh://user@host -i <private_key> --sudo
```
