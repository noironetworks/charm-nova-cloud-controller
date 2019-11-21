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

## Network Space support

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

## Default Quota Configuration

This charm supports default quota settings for projects.
This feature is only available from Openstack Icehouse and later releases.

The default quota settings do not overwrite post-deployment CLI quotas set by operators.
Existing projects whose quotas were not modified will adopt the new defaults when a config-changed hook occurs.
Newly created projects will also adopt the defaults set in the charm's config.

By default, the charm's quota configs are not set and openstack projects have the values below as default:
quota-instances - 10
quota-cores - 20
quota-ram - 51200
quota-metadata_items - 128
quota-injected_files - 5
quota-injected_file_content_bytes - 10240
quota-injected_file_path_length - 255
quota-key_pairs - 100
quota-server_groups - 10 (only available after Icehouse)
quota-server_group_members - 10 (only available after Icehouse)

## SSH knownhosts caching

This section covers the option involving the caching of SSH host lookups
(knownhosts) on each nova-compute unit.  Caching of SSH host lookups speeds up
deployment of nova-compute units when first deploying a cloud, and when adding
a new unit.

There is a Boolean configuration key `cache-known-hosts` that ensures that any
given host lookup to be performed just once.  The default is `true` which means
that caching is performed.

**Note**: A cloud can be deployed with the `cache-known-hosts` key set to
`false`, and be set to `true` post-deployment. At that point the hosts
will have been cached. The key only controls whether the cache is used or
not.

If the above key is set, a new Juju action `clear-unit-knownhost-cache` is
provided to clear the cache. This can be applied to a unit, service, or an
entire nova-cloud-controller application. This would be needed if DNS
resolution had changed in an existing cloud or during a cloud deployment.
Not clearing the cache in such cases could result in an inconsistent set
of knownhosts files.

This action will cause DNS resolution to be performed (for
unit/service/application), thus potentially triggering a relation-set on
the nova-cloud-controller unit(s) and subsequent changed hook on the
related nova-compute units.

The action is used as follows, based on unit, service, or application,
respectively:

```
juju run-action nova-cloud-controller/0 clear-unit-knownhost-cache target=nova-compute/2
juju run-action nova-cloud-controller/0 clear-unit-knownhost-cache target=nova-compute
juju run-action nova-cloud-controller/0 clear-unit-knownhost-cache
```

In a high-availability setup, the action must be run on all
`nova-cloud-controller` units.

# Policy Overrides

This feature allows for policy overrides using the `policy.d` directory.  This
is an **advanced** feature and the policies that the OpenStack service supports
should be clearly understood before trying to override, or add to, the default
policies that the service uses.  The charm also has some policy defaults.  They
should also be understood before being overridden.

> **Caution**: It is possible to break the system (for tenants and other
  services) if policies are incorrectly applied to the service.

Policy overrides are YAML files that contain rules that will add to, or
override, existing policy rules in the service.  The `policy.d` directory is
a place to put the YAML override files.  This charm owns the
`/etc/nova/policy.d` directory, and as such, any manual changes to it will
be overwritten on charm upgrades.

Overrides are provided to the charm using a Juju resource called
`policyd-override`.  The resource is a ZIP file.  This file, say
`overrides.zip`, is attached to the charm by:

    juju attach-resource nova-cloud-controller policyd-override=overrides.zip

The policy override is enabled in the charm using:

    juju config nova-cloud-controller use-policyd-override=true

When `use-policyd-override` is `True` the status line of the charm will be
prefixed with `PO:` indicating that policies have been overridden.  If the
installation of the policy override YAML files failed for any reason then the
status line will be prefixed with `PO (broken):`.  The log file for the charm
will indicate the reason.  No policy override files are installed if the `PO
(broken):` is shown.  The status line indicates that the overrides are broken,
not that the policy for the service has failed. The policy will be the defaults
for the charm and service.

Policy overrides on one service may affect the functionality of another
service. Therefore, it may be necessary to provide policy overrides for
multiple service charms to achieve a consistent set of policies across the
OpenStack system.  The charms for the other services that may need overrides
should be checked to ensure that they support overrides before proceeding.
