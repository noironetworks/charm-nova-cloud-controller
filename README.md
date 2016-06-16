# nova-cloud-controller

Cloud controller node for OpenStack nova. Contains nova-schedule, nova-api, nova-network and nova-objectstore.

If console access is required then console-proxy-ip should be set to a client accessible IP that resolves
to the nova-cloud-controller. If running in HA mode then the public vip is used if console-proxy-ip is set
to local. Note: The console access protocol is baked into a guest when it is created, if you change it then
console access for existing guests will stop working

**Special considerations to be deployed using Postgresql**

    juju deploy nova-cloud-controller
    juju deploy postgresql
    juju add-relation "nova-cloud-controller:pgsql-nova-db" "postgresql:db"
    juju add-relation "nova-cloud-controller:pgsql-neutron-db" "postgresql:db"

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
