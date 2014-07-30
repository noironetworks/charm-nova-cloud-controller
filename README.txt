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
