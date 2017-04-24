#  Docker EE (Standard/Advanced) InSpec Profiles

From the root of the inspec directory, the profiles below can be executed.

## FedRAMP

### Moderate Baseline

```sh
docker run -it --rm -v $(pwd):/share chef/inspec:latest exec FedRAMP/Moderate -t ssh://user@host -i <private_key> --sudo
```

### High Baseline

```sh
docker run -it --rm -v $(pwd):/share chef/inspec:latest exec FedRAMP/High -t ssh://user@host -i <private_key> --sudo
```
