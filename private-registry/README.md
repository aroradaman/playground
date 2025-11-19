# Docker Private Registry with TLS/SSL

The script starts a private registry with TLS, updates host, kind/capd nodes and kapp-controller deployment with the registry certificate for access to the registry. 

Note: root access will be required for host aliasing, password prompt is expected while running the script.
## Configuration

- **dest**: Sets the destination directory for certificates and registry data, defaults to "${HOME}/.private-registry".
- **alias**: Sets the CNAME for the registry, defaults to "registry.local"
- **netdev**: Sets the network interface name for fetching the IP address for host alias, defaults to "enp2s1"
