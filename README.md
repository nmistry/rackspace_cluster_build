rackspace_cluster_build
=======================

Describe a cloud environment in yaml and build it automagically

## installation
pip install -r requirements.txt

## usage
python rackspace_cluster_build.py --config environment.yaml

## configuration

Simple environment:
```
---
### simple.yml

rackspace_region: DFW
rackspace_credentials: ~/.rackspace_cloud_credentials

environment: example.com
ssh_keyname: emample_com
ssh_keyfile: ~/.ssh/id_rsa.pub

default_server_image: Ubuntu 12.04 LTS (Precise Pangolin)
default_server_flavor: 1 GB Performance

servers :
    - name: app01
```

for a more complex example look at example.yaml

## limitations
- have not recorded root password, must use ssh keys
- only one block storage device per host
- load balancers cant share a vip (yet)
- there is very little error checking, so its your job to make it work right (for now)
- poor documentation (for now)
