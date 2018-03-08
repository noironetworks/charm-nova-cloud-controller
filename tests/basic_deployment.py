# Copyright 2016 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import amulet
import json

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
)
from charmhelpers.contrib.openstack.utils import CompareOpenStackReleases

import keystoneclient
from keystoneclient.v3 import client as keystone_client_v3
import glanceclient
from novaclient import client as nova_client
from novaclient import exceptions


class NovaOpenStackAmuletUtils(OpenStackAmuletUtils):
    """Nova based helper extending base helper for creation of flavors"""

    def create_flavor(self, nova, name, ram, vcpus, disk, flavorid="auto",
                      ephemeral=0, swap=0, rxtx_factor=1.0, is_public=True):
        """Create the specified flavor."""
        try:
            nova.flavors.find(name=name)
        except (exceptions.NotFound, exceptions.NoUniqueMatch):
            self.log.debug('Creating flavor ({})'.format(name))
            nova.flavors.create(name, ram, vcpus, disk, flavorid,
                                ephemeral, swap, rxtx_factor, is_public)


# Use DEBUG to turn on debug logging
u = NovaOpenStackAmuletUtils(DEBUG)


class NovaCCBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic nova cloud controller deployment."""

    def __init__(self, series=None, openstack=None, source=None,
                 stable=True):
        """Deploy the entire test environment."""
        super(NovaCCBasicDeployment, self).__init__(series, openstack,
                                                    source, stable)
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        u.log.info('Waiting on extended status checks...')
        exclude_services = []
        self._auto_wait_for_status(exclude_services=exclude_services)

        self.d.sentry.wait()
        self._initialize_tests()

    def _assert_services(self, should_run):
        services = ["nova-api-os-compute", "nova-cert", "nova-conductor",
                    "nova-scheduler", "apache2", "haproxy"]
        cmp_os_release = CompareOpenStackReleases(
            self._get_openstack_release_string()
        )
        if cmp_os_release >= 'newton':
            services.remove('nova-cert')
        u.get_unit_process_ids(
            {self.nova_cc_sentry: services},
            expect_success=should_run)

    def _add_services(self):
        """Add services

           Add the services that we're testing, where nova-cc is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'nova-cloud-controller'}
        other_services = [
            {'name': 'rabbitmq-server'},
            {'name': 'nova-compute', 'units': 2},
            {'name': 'keystone'},
            {'name': 'glance'},
            {'name': 'percona-cluster', 'constraints': {'mem': '3072M'}},
        ]
        if self._get_openstack_release() >= self.xenial_ocata:
            other_ocata_services = [
                {'name': 'neutron-gateway'},
                {'name': 'neutron-api'},
                {'name': 'neutron-openvswitch'},
            ]
            other_services += other_ocata_services
        super(NovaCCBasicDeployment, self)._add_services(this_service,
                                                         other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'nova-cloud-controller:shared-db': 'percona-cluster:shared-db',
            'nova-cloud-controller:identity-service': 'keystone:'
                                                      'identity-service',
            'nova-cloud-controller:amqp': 'rabbitmq-server:amqp',
            'nova-cloud-controller:cloud-compute': 'nova-compute:'
                                                   'cloud-compute',
            'nova-cloud-controller:image-service': 'glance:image-service',
            'nova-compute:image-service': 'glance:image-service',
            'nova-compute:shared-db': 'percona-cluster:shared-db',
            'nova-compute:amqp': 'rabbitmq-server:amqp',
            'keystone:shared-db': 'percona-cluster:shared-db',
            'glance:identity-service': 'keystone:identity-service',
            'glance:shared-db': 'percona-cluster:shared-db',
            'glance:amqp': 'rabbitmq-server:amqp',
        }
        if self._get_openstack_release() >= self.xenial_ocata:
            ocata_relations = {
                'neutron-gateway:amqp': 'rabbitmq-server:amqp',
                'nova-cloud-controller:quantum-network-service':
                'neutron-gateway:quantum-network-service',
                'neutron-api:shared-db': 'percona-cluster:shared-db',
                'neutron-api:amqp': 'rabbitmq-server:amqp',
                'neutron-api:neutron-api': 'nova-cloud-controller:neutron-api',
                'neutron-api:identity-service': 'keystone:identity-service',
                'nova-compute:neutron-plugin': 'neutron-openvswitch:'
                                               'neutron-plugin',
                'rabbitmq-server:amqp': 'neutron-openvswitch:amqp',
            }
            relations.update(ocata_relations)
        super(NovaCCBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        nova_cc_config = {}
        nova_config = {}

        # Add some rate-limiting options to the charm. These will noop before
        # icehouse.
        nova_cc_config['api-rate-limit-rules'] = \
            "( POST, '*', .*, 9999, MINUTE );"

        if self._get_openstack_release() >= self.xenial_ocata:
            nova_cc_config['network-manager'] = 'Neutron'

        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}

        pxc_config = {
            'dataset-size': '25%',
            'max-connections': 1000,
            'root-password': 'ChangeMe123',
            'sst-password': 'ChangeMe123',
        }

        configs = {
            'nova-cloud-controller': nova_cc_config,
            'keystone': keystone_config,
            'nova-compute': nova_config,
            'percona-cluster': pxc_config,
        }

        super(NovaCCBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.pxc_sentry = self.d.sentry['percona-cluster'][0]
        self.keystone_sentry = self.d.sentry['keystone'][0]
        self.rabbitmq_sentry = self.d.sentry['rabbitmq-server'][0]
        self.nova_cc_sentry = self.d.sentry['nova-cloud-controller'][0]
        self.nova_compute_sentry = self.d.sentry['nova-compute'][0]
        self.glance_sentry = self.d.sentry['glance'][0]

        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))

        # Authenticate admin with keystone
        self.keystone_session, self.keystone = u.get_default_keystone_session(
            self.keystone_sentry,
            openstack_release=self._get_openstack_release())

        # Authenticate admin with glance endpoint
        self.glance = glanceclient.Client('1', session=self.keystone_session)

        # Authenticate admin with nova endpoint
        self.nova = nova_client.Client(2, session=self.keystone_session)

        keystone_ip = self.keystone_sentry.info['public-address']

        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        self.demo_project = 'demoProject'
        self.demo_domain = 'demoDomain'
        if self._get_openstack_release() >= self.xenial_queens:
            self.create_users_v3()
            self.demo_user_session, auth = u.get_keystone_session(
                keystone_ip,
                self.demo_user,
                'password',
                api_version=3,
                user_domain_name=self.demo_domain,
                project_domain_name=self.demo_domain,
                project_name=self.demo_project
            )
            self.keystone_demo = keystone_client_v3.Client(
                session=self.demo_user_session)
            self.nova_demo = nova_client.Client(
                2,
                session=self.demo_user_session)
        else:
            self.create_users_v2()
            # Authenticate demo user with keystone
            self.keystone_demo = \
                u.authenticate_keystone_user(
                    self.keystone, user=self.demo_user,
                    password='password',
                    tenant=self.demo_tenant)
            # Authenticate demo user with nova-api
            self.nova_demo = u.authenticate_nova_user(self.keystone,
                                                      user=self.demo_user,
                                                      password='password',
                                                      tenant=self.demo_tenant)

    def create_users_v3(self):
        try:
            self.keystone.projects.find(name=self.demo_project)
        except keystoneclient.exceptions.NotFound:
            domain = self.keystone.domains.create(
                self.demo_domain,
                description='Demo Domain',
                enabled=True
            )
            project = self.keystone.projects.create(
                self.demo_project,
                domain,
                description='Demo Project',
                enabled=True,
            )
            user = self.keystone.users.create(
                self.demo_user,
                domain=domain.id,
                project=self.demo_project,
                password='password',
                email='demov3@demo.com',
                description='Demo',
                enabled=True)
            role = self.keystone.roles.find(name='Admin')
            self.keystone.roles.grant(
                role.id,
                user=user.id,
                project=project.id)

    def create_users_v2(self):
        if not u.tenant_exists(self.keystone, self.demo_tenant):
            tenant = self.keystone.tenants.create(tenant_name=self.demo_tenant,
                                                  description='demo tenant',
                                                  enabled=True)

            self.keystone.roles.create(name=self.demo_role)
            self.keystone.users.create(name=self.demo_user,
                                       password='password',
                                       tenant_id=tenant.id,
                                       email='demo@demo.com')

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        u.log.debug('Checking system services on units...')
        services = {
            self.rabbitmq_sentry: ['rabbitmq-server'],
            self.nova_cc_sentry: ['nova-api-ec2',
                                  'nova-api-os-compute',
                                  'nova-conductor',
                                  'nova-objectstore',
                                  'nova-cert',
                                  'nova-scheduler'],
            self.nova_compute_sentry: ['nova-compute',
                                       'nova-network',
                                       'nova-api'],
            self.keystone_sentry: ['keystone'],
            self.glance_sentry: ['glance-registry', 'glance-api']
        }
        cmp_os_release = CompareOpenStackReleases(
            self._get_openstack_release_string()
        )
        if cmp_os_release >= 'liberty':
            services[self.nova_cc_sentry].remove('nova-api-ec2')
            services[self.nova_cc_sentry].remove('nova-objectstore')

        if cmp_os_release >= 'newton':
            services[self.nova_cc_sentry].remove('nova-cert')

        if self._get_openstack_release() >= self.trusty_liberty:
            services[self.keystone_sentry] = ['apache2']

        if self._get_openstack_release() >= self.xenial_ocata:
            services[self.nova_compute_sentry].remove('nova-network')
            services[self.nova_compute_sentry].remove('nova-api')

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_102_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        u.log.debug('Checking keystone service catalog...')
        endpoint_vol = {'adminURL': u.valid_url,
                        'region': 'RegionOne',
                        'id': u.not_null,
                        'publicURL': u.valid_url,
                        'internalURL': u.valid_url}
        endpoint_id = {'adminURL': u.valid_url,
                       'region': 'RegionOne',
                       'id': u.not_null,
                       'publicURL': u.valid_url,
                       'internalURL': u.valid_url}

        if self._get_openstack_release() >= self.trusty_kilo:
            expected = {'compute': [endpoint_vol], 'identity': [endpoint_id]}
        else:
            expected = {'s3': [endpoint_vol], 'compute': [endpoint_vol],
                        'ec2': [endpoint_vol], 'identity': [endpoint_id]}

        actual = self.keystone.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(
            expected,
            actual,
            openstack_release=self._get_openstack_release())
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_104_openstack_compute_api_endpoint(self):
        """Verify the openstack compute api (osapi) endpoint data."""
        u.log.debug('Checking compute endpoint data...')

        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8774'

        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }

        ret = u.validate_endpoint_data(
            endpoints,
            admin_port,
            internal_port,
            public_port,
            expected,
            openstack_release=self._get_openstack_release())

        if ret:
            message = 'osapi endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_106_ec2_api_endpoint(self):
        """Verify the EC2 api endpoint data."""
        if self._get_openstack_release() >= self.trusty_kilo:
            return

        u.log.debug('Checking ec2 endpoint data...')
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8773'

        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'EC2 endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_108_s3_api_endpoint(self):
        """Verify the S3 api endpoint data."""
        if self._get_openstack_release() >= self.trusty_kilo:
            return

        u.log.debug('Checking s3 endpoint data...')
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '3333'
        expected = {
            'id': u.not_null,
            'region': 'RegionOne',
            'adminurl': u.valid_url,
            'internalurl': u.valid_url,
            'publicurl': u.valid_url,
            'service_id': u.not_null
        }

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'S3 endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_110_memcache(self):
        u.validate_memcache(self.nova_cc_sentry,
                            '/etc/nova/nova.conf',
                            self._get_openstack_release(),
                            earliest_release=self.trusty_mitaka)

    def test_200_nova_cc_shared_db_relation(self):
        """Verify the nova-cc to mysql shared-db relation data"""
        u.log.debug('Checking n-c-c:mysql db relation data...')
        unit = self.nova_cc_sentry
        relation = ['shared-db', 'percona-cluster:shared-db']

        expected = {
            'private-address': u.valid_ip,
            'nova_database': 'nova',
            'nova_username': 'nova',
            'nova_hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_mysql_shared_db_relation(self):
        """Verify the mysql to nova-cc shared-db relation data"""
        u.log.debug('Checking mysql:n-c-c db relation data...')
        unit = self.pxc_sentry
        relation = ['shared-db', 'nova-cloud-controller:shared-db']
        expected = {
            'private-address': u.valid_ip,
            'nova_password': u.not_null,
            'db_host': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('mysql shared-db', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_204_nova_cc_identity_service_relation(self):
        """Verify the nova-cc to keystone identity-service relation data"""
        u.log.debug('Checking n-c-c:keystone identity relation data...')
        unit = self.nova_cc_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'nova_internal_url': u.valid_url,
            'nova_public_url': u.valid_url,
            'nova_service': 'nova',
            'private-address': u.valid_ip,
            'nova_region': 'RegionOne',
            'nova_admin_url': u.valid_url,
        }
        if self._get_openstack_release() < self.trusty_kilo:
            expected['s3_admin_url'] = u.valid_url
            expected['s3_internal_url'] = u.valid_url
            expected['s3_public_url'] = u.valid_url
            expected['s3_region'] = 'RegionOne'
            expected['s3_service'] = 's3'
            expected['ec2_admin_url'] = u.valid_url
            expected['ec2_internal_url'] = u.valid_url
            expected['ec2_public_url'] = u.valid_url
            expected['ec2_region'] = 'RegionOne'
            expected['ec2_service'] = 'ec2'

        if self._get_openstack_release() >= self.xenial_ocata:
            expected['placement_service'] = 'placement'
            expected['placement_internal_url'] = u.valid_url
            expected['placement_public_url'] = u.valid_url
            expected['placement_admin_url'] = u.valid_url
            expected['placement_region'] = 'RegionOne'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_206_keystone_identity_service_relation(self):
        """Verify the keystone to nova-cc identity-service relation data"""
        u.log.debug('Checking keystone:n-c-c identity relation data...')
        unit = self.keystone_sentry
        relation = ['identity-service',
                    'nova-cloud-controller:identity-service']
        expected = {
            'service_protocol': 'http',
            'service_tenant': 'services',
            'admin_token': 'ubuntutesting',
            'service_password': u.not_null,
            'service_port': '5000',
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'auth_host': u.valid_ip,
            'service_username': 'ec2_nova_s3',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }
        if self._get_openstack_release() >= self.trusty_kilo:
            expected['service_username'] = 'nova'

        if self._get_openstack_release() >= self.xenial_ocata:
            expected['service_username'] = 'nova_placement'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_208_nova_cc_amqp_relation(self):
        """Verify the nova-cc to rabbitmq-server amqp relation data"""
        u.log.debug('Checking n-c-c:rmq amqp relation data...')
        unit = self.nova_cc_sentry
        relation = ['amqp', 'rabbitmq-server:amqp']
        expected = {
            'username': 'nova',
            'private-address': u.valid_ip,
            'vhost': 'openstack'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_210_rabbitmq_amqp_relation(self):
        """Verify the rabbitmq-server to nova-cc amqp relation data"""
        u.log.debug('Checking rmq:n-c-c amqp relation data...')
        unit = self.rabbitmq_sentry
        relation = ['amqp', 'nova-cloud-controller:amqp']
        expected = {
            'private-address': u.valid_ip,
            'password': u.not_null,
            'hostname': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('rabbitmq amqp', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_212_nova_cc_cloud_compute_relation(self):
        """Verify the nova-cc to nova-compute cloud-compute relation data"""
        u.log.debug('Checking n-c-c:nova-compute '
                    'cloud-compute relation data...')

        unit = self.nova_cc_sentry
        relation = ['cloud-compute', 'nova-compute:cloud-compute']
        expected = {
            'volume_service': 'cinder',
            'network_manager': 'flatdhcpmanager',
            'ec2_host': u.valid_ip,
            'private-address': u.valid_ip,
            'restart_trigger': u.not_null
        }
        if self._get_openstack_release() >= self.xenial_ocata:
            expected['network_manager'] = 'neutron'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_214_nova_cloud_compute_relation(self):
        """Verify the nova-compute to nova-cc cloud-compute relation data"""
        u.log.debug('Checking nova-compute:n-c-c '
                    'cloud-compute relation data...')

        unit = self.nova_compute_sentry
        relation = ['cloud-compute', 'nova-cloud-controller:cloud-compute']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-compute cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_216_nova_cc_image_service_relation(self):
        """Verify the nova-cc to glance image-service relation data"""
        u.log.debug('Checking n-c-c:glance image-service relation data...')
        unit = self.nova_cc_sentry
        relation = ['image-service', 'glance:image-service']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc image-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_218_glance_image_service_relation(self):
        """Verify the glance to nova-cc image-service relation data"""
        u.log.debug('Checking glance:n-c-c image-service relation data...')
        unit = self.glance_sentry
        relation = ['image-service', 'nova-cloud-controller:image-service']
        expected = {
            'private-address': u.valid_ip,
            'glance-api-server': u.valid_url
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('glance image-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_300_nova_default_config(self):
        """Verify the data in the nova config file's default section."""
        u.log.debug('Checking nova config file data...')
        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'

        rmq_ncc_rel = self.rabbitmq_sentry.relation(
            'amqp', 'nova-cloud-controller:amqp')

        gl_ncc_rel = self.glance_sentry.relation(
            'image-service', 'nova-cloud-controller:image-service')

        # Since >= liberty endpoint_type was replaced by interface
        # https://github.com/openstack/keystoneauth/commit/d227f6d237c4309b21a32a115fc5b09b9ba46ef0
        try:
            ks_ep = self.keystone.service_catalog.url_for(
                service_type='identity', interface='publicURL')
        except TypeError:
            ks_ep = self.keystone.service_catalog.url_for(
                service_type='identity', endpoint_type='publicURL')

        ks_ec2 = "{}/ec2tokens".format(ks_ep)

        ks_ncc_rel = self.keystone_sentry.relation(
            'identity-service', 'nova-cloud-controller:identity-service')

        ks_uri = "http://{}:{}/".format(ks_ncc_rel['service_host'],
                                        ks_ncc_rel['service_port'])

        id_uri = "{}://{}:{}/".format(ks_ncc_rel['auth_protocol'],
                                      ks_ncc_rel['service_host'],
                                      ks_ncc_rel['auth_port'])

        db_ncc_rel = self.pxc_sentry.relation(
            'shared-db', 'nova-cloud-controller:shared-db')

        db_uri = "mysql://{}:{}@{}/{}".format('nova',
                                              db_ncc_rel['nova_password'],
                                              db_ncc_rel['db_host'],
                                              'nova')

        expected = {
            'DEFAULT': {
                'dhcpbridge_flagfile': '/etc/nova/nova.conf',
                'dhcpbridge': '/usr/bin/nova-dhcpbridge',
                'logdir': '/var/log/nova',
                'state_path': '/var/lib/nova',
                'force_dhcp_release': 'True',
                'iscsi_helper': 'tgtadm',
                'libvirt_use_virtio_for_bridges': 'True',
                'connection_type': 'libvirt',
                'root_helper': 'sudo nova-rootwrap /etc/nova/rootwrap.conf',
                'verbose': 'False',
                'debug': 'False',
                'api_paste_config': '/etc/nova/api-paste.ini',
                'volumes_path': '/var/lib/nova/volumes',
                'auth_strategy': 'keystone',
                'compute_driver': 'libvirt.LibvirtDriver',
                'network_manager': 'nova.network.manager.FlatDHCPManager',
                's3_listen_port': '3323',
                'osapi_compute_listen_port': '8764',
            }
        }

        if self._get_openstack_release() < self.trusty_kilo:
            # Juno and earlier
            expected['database'] = {
                'connection': db_uri
            }
            expected['keystone_authtoken'] = {
                'auth_uri': ks_uri,
                'auth_host': ks_ncc_rel['service_host'],
                'auth_port': ks_ncc_rel['auth_port'],
                'auth_protocol': ks_ncc_rel['auth_protocol'],
                'admin_tenant_name': ks_ncc_rel['service_tenant'],
                'admin_user': ks_ncc_rel['service_username'],
                'admin_password': ks_ncc_rel['service_password'],
            }
            expected['DEFAULT'].update({
                'lock_path': '/var/lock/nova',
                'libvirt_use_virtio_for_bridges': 'True',
                'compute_driver': 'libvirt.LibvirtDriver',
                'rabbit_userid': 'nova',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rmq_ncc_rel['password'],
                'rabbit_host': rmq_ncc_rel['hostname'],
                'glance_api_servers': gl_ncc_rel['glance-api-server']
            })
        else:
            # Kilo and later
            expected['database'] = {
                'connection': db_uri,
                'max_pool_size': u.not_null,
            }
            expected['glance'] = {
                'api_servers': gl_ncc_rel['glance-api-server'],
            }
            expected['keystone_authtoken'] = {
                'identity_uri': id_uri.rstrip('/'),
                'auth_uri': ks_uri,
                'admin_tenant_name': ks_ncc_rel['service_tenant'],
                'admin_user': ks_ncc_rel['service_username'],
                'admin_password': ks_ncc_rel['service_password'],
                'signing_dir': '/var/cache/nova',
            }
            expected['osapi_v3'] = {
                'enabled': 'True',
            }
            # due to worker multiplier changes and the way the unit changes
            # depending on whether it is LXC or KVM, we can't actually guess
            # the workers reliable.
            expected['conductor'] = {
                'workers': u.not_null,
            }
            expected['oslo_messaging_rabbit'] = {
                'rabbit_userid': 'nova',
                'rabbit_virtual_host': 'openstack',
                'rabbit_password': rmq_ncc_rel['password'],
                'rabbit_host': rmq_ncc_rel['hostname'],
            }
            expected['oslo_concurrency'] = {
                'lock_path': '/var/lock/nova',
            }

        if self._get_openstack_release() >= self.xenial_queens:
            expected['keystone_authtoken'] = {
                'auth_uri': ks_uri.rstrip('/'),
                'auth_url': id_uri.rstrip('/'),
                'auth_type': 'password',
                'project_domain_name': 'service_domain',
                'user_domain_name': 'service_domain',
                'project_name': 'services',
                'username': ks_ncc_rel['service_username'],
                'password': ks_ncc_rel['service_password'],
                'signing_dir': '/var/cache/nova'
            }
        elif self._get_openstack_release() >= self.trusty_mitaka:
            expected['keystone_authtoken'] = {
                'auth_uri': ks_uri.rstrip('/'),
                'auth_url': id_uri.rstrip('/'),
                'auth_type': 'password',
                'project_domain_name': 'default',
                'user_domain_name': 'default',
                'project_name': 'services',
                'username': ks_ncc_rel['service_username'],
                'password': ks_ncc_rel['service_password'],
                'signing_dir': '/var/cache/nova'
            }
        elif self._get_openstack_release() >= self.trusty_liberty:
            # Liberty
            expected['keystone_authtoken'] = {
                'auth_uri': ks_uri.rstrip('/'),
                'auth_url': id_uri.rstrip('/'),
                'auth_plugin': 'password',
                'project_domain_id': 'default',
                'user_domain_id': 'default',
                'project_name': 'services',
                'username': 'nova',
                'password': ks_ncc_rel['service_password'],
                'signing_dir': '/var/cache/nova',
            }

        if self._get_openstack_release() < self.trusty_mitaka:
            expected['DEFAULT'].update({
                'ec2_private_dns_show_ip': 'True',
                'enabled_apis': 'ec2,osapi_compute,metadata',
                'keystone_ec2_url': ks_ec2,
                'ec2_listen_port': '8763'
            })
        elif self._get_openstack_release() >= self.trusty_mitaka:
            expected['DEFAULT'].update({
                'enabled_apis': 'osapi_compute,metadata',
            })

        if self._get_openstack_release() >= self.xenial_ocata:
            del expected['DEFAULT']['force_dhcp_release']
            del expected['DEFAULT']['network_manager']
            del expected['oslo_messaging_rabbit']
            expected['DEFAULT']['transport_url'] = u.not_null
            del expected['DEFAULT']['auth_strategy']
            expected['api'] = {'auth_strategy': 'keystone'}
            del expected['DEFAULT']['api_paste_config']
            expected['wsgi'] = {'api_paste_config': '/etc/nova/api-paste.ini'}

        for section, pairs in expected.iteritems():
            ret = u.validate_config_data(unit, conf, section, pairs)
            if ret:
                message = "nova config error: {}".format(ret)
                amulet.raise_status(amulet.FAIL, msg=message)

    def test_302_api_rate_limiting_is_enabled(self):
        """
        Check that API rate limiting is enabled.
        """
        u.log.debug('Checking api-paste config file data...')

        unit = self.nova_cc_sentry
        conf = '/etc/nova/api-paste.ini'

        if self._get_openstack_release() >= self.trusty_mitaka:
            section = "filter:legacy_ratelimit"
        else:
            section = "filter:ratelimit"

        factory = ("nova.api.openstack.compute.limits:RateLimitingMiddleware"
                   ".factory")

        expected = {"paste.filter_factory": factory,
                    "limits": "( POST, '*', .*, 9999, MINUTE );"}

        ret = u.validate_config_data(unit, conf, section, expected)
        if ret:
            message = "api paste config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_310_pci_alias_config(self):
        """Verify the pci alias data is rendered properly."""
        u.log.debug('Checking pci aliases in nova config')

        os_release = self._get_openstack_release_string()
        if CompareOpenStackReleases(os_release) < 'kilo':
            u.log.info('Skipping test, {} < kilo'.format(os_release))
            return

        _pci_alias1 = {
            "name": "IntelNIC",
            "capability_type": "pci",
            "product_id": "1111",
            "vendor_id": "8086",
            "device_type": "type-PF"}

        if CompareOpenStackReleases(os_release) >= 'ocata':
            section = "pci"
            key_name = "alias"
        else:
            section = "DEFAULT"
            key_name = "pci_alias"

        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'
        self.d.configure(
            'nova-cloud-controller',
            {'pci-alias': json.dumps(_pci_alias1, sort_keys=True)})
        self.d.sentry.wait()
        ret = u.validate_config_data(
            unit,
            conf,
            section,
            {key_name: ('{"capability_type": "pci", "device_type": "type-PF", '
                        '"name": "IntelNIC", "product_id": "1111", '
                        '"vendor_id": "8086"}')})
        if ret:
            message = "PCI Alias config error in section {}: {}".format(
                section,
                ret)
            amulet.raise_status(amulet.FAIL, msg=message)
        self.d.configure('nova-cloud-controller', {'pci-alias': ''})

    def test_400_image_instance_create(self):
        """Create an image/instance, verify they exist, and delete them."""
        u.log.debug('Checking nova instance creation...')

        image = u.create_cirros_image(self.glance, "cirros-image")
        if not image:
            amulet.raise_status(amulet.FAIL, msg="Image create failed")

        # Ensure required flavor exists, required for >= newton
        u.create_flavor(nova=self.nova,
                        name='m1.tiny', ram=512, vcpus=1, disk=1)

        instance = u.create_instance(self.nova_demo, "cirros-image", "cirros",
                                     "m1.tiny")
        if not instance:
            amulet.raise_status(amulet.FAIL, msg="Instance create failed")

        found = False
        for instance in self.nova_demo.servers.list():
            if instance.name == 'cirros':
                found = True
                if instance.status != 'ACTIVE':
                    msg = "cirros instance is not active"
                    amulet.raise_status(amulet.FAIL, msg=msg)

        if not found:
            message = "nova cirros instance does not exist"
            amulet.raise_status(amulet.FAIL, msg=message)

        u.delete_resource(self.glance.images, image.id,
                          msg="glance image")

        u.delete_resource(self.nova_demo.servers, instance.id,
                          msg="nova instance")

    def test_900_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed."""
        u.log.info('Checking that conf files and system services respond '
                   'to a charm config change...')

        sentry = self.nova_cc_sentry
        juju_service = 'nova-cloud-controller'

        # Process names, corresponding conf files
        conf_file = '/etc/nova/nova.conf'
        services = {
            'nova-api-ec2': conf_file,
            'nova-api-os-compute': conf_file,
            'nova-objectstore': conf_file,
            'nova-cert': conf_file,
            'nova-scheduler': conf_file,
            'nova-conductor': conf_file
        }

        cmp_os_release = CompareOpenStackReleases(
            self._get_openstack_release_string()
        )
        if cmp_os_release >= 'liberty':
            del services['nova-api-ec2']
            del services['nova-objectstore']

        if cmp_os_release >= 'newton':
            del services['nova-cert']

        if self._get_openstack_release() >= self.xenial_ocata:
            # nova-placement-api is run under apache2 with mod_wsgi
            services['apache2'] = conf_file

        # Expected default and alternate values
        flags_default = 'quota_cores=20,quota_instances=40,quota_ram=102400'
        flags_alt = 'quota_cores=10,quota_instances=20,quota_ram=51200'
        set_default = {'config-flags': flags_default}
        set_alternate = {'config-flags': flags_alt}

        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        sleep_time = 60
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     sleep_time=sleep_time):
                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)
            sleep_time = 0

        self.d.configure(juju_service, set_default)

    def test_901_pause_resume(self):
        """Test pause and resume actions."""
        self._assert_services(should_run=True)
        action_id = u.run_action(self.nova_cc_sentry, "pause")
        assert u.wait_on_action(action_id), "Pause action failed."

        self._assert_services(should_run=False)

        action_id = u.run_action(self.nova_cc_sentry, "resume")
        assert u.wait_on_action(action_id), "Resume action failed"
        self._assert_services(should_run=True)
