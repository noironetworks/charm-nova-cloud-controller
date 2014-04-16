=====================
nova-cloud-controller
=====================

Cloud controller node for Openstack nova. Contains nova-schedule, nova-api, nova-network and nova-objectstore.

******************************************************
Special considerations to be deployed using Postgresql
******************************************************

juju deploy nova-cloud-controller
juju deploy postgresql

juju add-relation "nova-cloud-controller:pgsql-nova-db" "postgresql:db"
juju add-relation "nova-cloud-controller:pgsql-neutron-db" "postgresql:db"
