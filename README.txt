=====================
nova-cloud-controller
=====================

Cloud controller node for Openstack nova. Contains nova-schedule, nova-api, nova-network and nova-objectstore.

The neutron-api interface can be used join this charm with an external neutron-api server. If this is done
then this charm will shutdown its neutron-api service and the external charm will be registered as the
neutron-api endpoint in keystone. It will also use the quantum-security-groups setting which is passed to
it by the api service rather than its own quantum-security-groups setting.

If console access is required then console-proxy-ip should be set to a client accessible IP that resolves
to the nova-cloud-controller. If running in HA mode then the public vip is used if console-proxy-ip is set
to local. Note: The console access protocol is baked into a guest when it is created, if you change it then
console access for existing guests will stop working

******************************************************
Special considerations to be deployed using Postgresql
******************************************************

juju deploy nova-cloud-controller
juju deploy postgresql

juju add-relation "nova-cloud-controller:pgsql-nova-db" "postgresql:db"
juju add-relation "nova-cloud-controller:pgsql-neutron-db" "postgresql:db"

Deploying from source
=====================

The minimum openstack-origin-git config required to deploy from source is:

  openstack-origin-git:
      "repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: stable/juno}
         - {name: nova,
            repository: 'git://git.openstack.org/openstack/nova',
            branch: stable/juno}"

Note that there are only two 'name' values the charm knows about: 'requirements'
and 'nova'. These repositories must correspond to these 'name' values.
Additionally, the requirements repository must be specified first and the
nova repository must be specified last. All other repostories are installed
in the order in which they are specified.

The following is a full list of current tip repos (may not be up-to-date):

  openstack-origin-git:
      "repositories:
         - {name: requirements,
            repository: 'git://git.openstack.org/openstack/requirements',
            branch: master}
         - {name: oslo-concurrency,
            repository: 'git://git.openstack.org/openstack/oslo.concurrency',
            branch: master}
         - {name: oslo-config,
            repository: 'git://git.openstack.org/openstack/oslo.config',
            branch: master}
         - {name: oslo-context,
            repository: 'git://git.openstack.org/openstack/oslo.context.git',
            branch: master}
         - {name: oslo-db,
            repository: 'git://git.openstack.org/openstack/oslo.db',
            branch: master}
         - {name: oslo-i18n,
            repository: 'git://git.openstack.org/openstack/oslo.i18n',
            branch: master}
         - {name: oslo-log,
            repository: 'git://git.openstack.org/openstack/oslo.log',
            branch: master}
         - {name: oslo-messaging,
            repository: 'git://git.openstack.org/openstack/oslo.messaging.git',
            branch: master}
         - {name: oslo-middleware,
            repository': 'git://git.openstack.org/openstack/oslo.middleware.git',
            branch: master}
         - {name: oslo-rootwrap',
            repository: 'git://git.openstack.org/openstack/oslo.rootwrap.git',
            branch: master}
         - {name: oslo-serialization,
            repository: 'git://git.openstack.org/openstack/oslo.serialization',
            branch: master}
         - {name: oslo-utils,
            repository: 'git://git.openstack.org/openstack/oslo.utils',
            branch: master}
         - {name: pbr,
            repository: 'git://git.openstack.org/openstack-dev/pbr',
            branch: master}
         - {name: stevedore,
            repository: 'git://git.openstack.org/openstack/stevedore.git',
            branch: 'master'}
         - {name: sqlalchemy-migrate,
            repository: 'git://git.openstack.org/stackforge/sqlalchemy-migrate',
            branch: master}
         - {name: python-cinderclient,
            repository: 'git://git.openstack.org/openstack/python-cinderclient.git',
            branch: master}
         - {name: python-glanceclient,
            repository': 'git://git.openstack.org/openstack/python-glanceclient.git',
            branch: master}
         - {name: python-neutronlient,
            repository': 'git://git.openstack.org/openstack/python-neutronclient.git',
            branch: master}
         - {name: keystonemiddleware,
            repository: 'git://git.openstack.org/openstack/keystonemiddleware',
            branch: master}
         - {name: nova,
            repository: 'git://git.openstack.org/openstack/nova',
            branch: master}"
