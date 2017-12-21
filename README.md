# nova-cloud-controller

Cloud controller node for OpenStack nova. Contains nova-schedule, nova-api, nova-network and nova-objectstore.

If console access is required then console-proxy-ip should be set to a client accessible IP that resolves
to the nova-cloud-controller. If running in HA mode then the public vip is used if console-proxy-ip is set
to local. Note: The console access protocol is baked into a guest when it is created, if you change it then
console access for existing guests will stop working

## HA/Clustering

There are two mutually exclusive high availability options: using virtual
IP(s) or DNS. In both cases, a relationship to hacluster is required which
provides the corosync back end HA functionality.

To use virtual IP(s) the clustered nodes must be on the same subnet such that
the VIP is a valid IP on the subnet for one of the node's interfaces and each
node has an interface in said subnet. The VIP becomes a highly-available API
endpoint.

At a minimum, the config option 'vip' must be set in order to use virtual IP
HA. If multiple networks are being used, a VIP should be provided for each
network, separated by spaces. Optionally, vip_iface or vip_cidr may be
specified.

To use DNS high availability there are several prerequisites. However, DNS HA
does not require the clustered nodes to be on the same subnet.
Currently the DNS HA feature is only available for MAAS 2.0 or greater
environments. MAAS 2.0 requires Juju 2.0 or greater. The clustered nodes must
have static or "reserved" IP addresses registered in MAAS. The DNS hostname(s)
must be pre-registered in MAAS before use with DNS HA.

At a minimum, the config option 'dns-ha' must be set to true and at least one
of 'os-public-hostname', 'os-internal-hostname' or 'os-internal-hostname' must
be set in order to use DNS HA. One or more of the above hostnames may be set.

The charm will throw an exception in the following circumstances:
If neither 'vip' nor 'dns-ha' is set and the charm is related to hacluster
If both 'vip' and 'dns-ha' are set as they are mutually exclusive
If 'dns-ha' is set and none of the os-{admin,internal,public}-hostname(s) are
set

# Network Space support

This charm supports the use of Juju Network Spaces, allowing the charm to be bound to network space configurations managed directly by Juju.  This is only supported with Juju 2.0 and above.

API endpoints can be bound to distinct network spaces supporting the network separation of public, internal and admin endpoints.

Access to the underlying MySQL instance can also be bound to a specific space using the shared-db relation.

To use this feature, use the --bind option when deploying the charm:

    juju deploy nova-cloud-controller --bind "public=public-space internal=internal-space admin=admin-space shared-db=internal-space"

alternatively these can also be provided as part of a juju native bundle configuration:

    nova-cloud-controller:
      charm: cs:xenial/nova-cloud-controller
      num_units: 1
      bindings:
        public: public-space
        admin: admin-space
        internal: internal-space
        shared-db: internal-space

NOTE: Spaces must be configured in the underlying provider prior to attempting to use them.

NOTE: Existing deployments using os-*-network configuration options will continue to function; these options are preferred over any network space binding provided if set.
