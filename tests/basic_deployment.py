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
import tempfile
import os

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
)
from charmhelpers.contrib.openstack.utils import CompareOpenStackReleases
from oslo_config import cfg

import keystoneclient
from keystoneclient.v3 import client as keystone_client_v3
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
        self.exclude_services = []
        self._auto_wait_for_status(exclude_services=self.exclude_services)

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
        if cmp_os_release >= 'rocky':
            services.remove('nova-api-os-compute')
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
            self.get_percona_service_entry(),
        ]
        if self._get_openstack_release() >= self.xenial_ocata:
            other_ocata_services = [
                {'name': 'neutron-gateway'},
                {'name': 'neutron-api'},
                {'name': 'neutron-openvswitch'},
            ]
            other_services += other_ocata_services
        if self._get_openstack_release() >= self.bionic_train:
            other_train_services = [
                {'name': 'placement'},
            ]
            other_services += other_train_services
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
        if self._get_openstack_release() >= self.bionic_train:
            train_relations = {
                'placement:shared-db': 'percona-cluster:shared-db',
                'placement:identity-service': 'keystone:identity-service',
                'placement:placement': 'nova-cloud-controller:placement',
            }
            relations.update(train_relations)
        super(NovaCCBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        nova_cc_config = {}
        nova_config = {}
        placement_config = {}

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
        if self._get_openstack_release() >= self.bionic_train:
            configs['placement'] = placement_config

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

        force_v1_client = False
        if self._get_openstack_release() == self.trusty_icehouse:
            # Updating image properties (such as arch or hypervisor) using the
            # v2 api in icehouse results in:
            # https://bugs.launchpad.net/python-glanceclient/+bug/1371559
            u.log.debug('Forcing glance to use v1 api')
            force_v1_client = True

        # Authenticate admin with glance endpoint
        self.glance = u.authenticate_glance_admin(
            self.keystone,
            force_v1_client=force_v1_client)

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
            self.glance_sentry: ['glance-api']
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

        if self._get_openstack_release() >= self.bionic_rocky:
            services[self.nova_cc_sentry].remove('nova-api-os-compute')
            services[self.nova_cc_sentry].append('apache2')

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

        if (self._get_openstack_release() >= self.xenial_ocata and
                self._get_openstack_release() <= self.disco_stein):
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

        if (self._get_openstack_release() >= self.xenial_ocata and
                self._get_openstack_release() <= self.disco_stein):
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

    def test_220_nova_metadata_propagate(self):
        """Verify that the setting vendor_data is propagated to nova-compute"""

        os_release = self._get_openstack_release()

        expected = {
            "vendordata_providers": "StaticJSON,DynamicJSON",
            "vendordata_dynamic_targets": "http://example.org/vdata",
            "vendordata_jsonfile_path": "/etc/nova/vendor_data.json",
        }

        u.log.debug('Validating the config does not exist prior to test')
        if self._get_openstack_release() < self.bionic_rocky:
            sentries = [self.nova_compute_sentry]
        else:
            sentries = [self.nova_compute_sentry, self.nova_cc_sentry]

        for sentry in sentries:
            # Validate nova-cc and nova-compute don't have vendor_data set
            if u.validate_config_data(
                    sentry, "/etc/nova/nova.conf", "api", expected) is None:
                amulet.raise_status(
                    amulet.FAIL, msg="Matching config options were found in "
                                     "nova.conf prior to the test.")
                content = u.file_contents_safe(
                    sentry, "/etc/nova/vendor_data.json", max_wait=4,
                    fatal=False)
                if content:
                    amulet.raise_status(
                        amulet.FAIL, msg="vendor_data.json exists with content"
                                         "prior to test: {}.".format(content))

        config = {
            'vendor-data': '{"good": "json"}',
            'vendor-data-url': 'http://example.org/vdata',
        }
        u.log.debug('Setting nova-cloud-controller config {}'.format(config))
        self.d.configure('nova-cloud-controller', config)

        u.log.debug('Waiting for all units to get ready')
        self.d.sentry.wait()

        u.log.debug('Validating the config has been applied and propagated')
        for sentry in sentries:
            # Validate config got propagated to nova-compute
            output = u.validate_config_data(sentry, "/etc/nova/nova.conf",
                                            "api", expected)

            if output is not None and os_release >= self.xenial_queens:
                amulet.raise_status(
                    amulet.FAIL, msg="Matching config options "
                                     "were not found in nova.conf. "
                                     "Output: {}".format(output))
            content = u.file_contents_safe(
                sentry, "/etc/nova/vendor_data.json", max_wait=4, fatal=True)
            if os_release >= self.xenial_queens:
                if not content or content != '{"good": "json"}':
                    amulet.raise_status(
                        amulet.FAIL, msg="vendor_data.json content did not "
                                         "match: {}.".format(content))

        u.log.debug('Test 220 finished successfully')

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

        CONF = cfg.CONF
        opt_group = cfg.OptGroup(name=section)
        pci_opts = [cfg.MultiStrOpt(key_name)]
        CONF.register_group(opt_group)
        CONF.register_opts(pci_opts, opt_group)

        _pci_alias2 = {
            "name": " Cirrus Logic ",
            "capability_type": "pci",
            "product_id": "0ff2",
            "vendor_id": "10de",
            "device_type": "type-PCI"}

        _pci_alias_list = "[{}, {}]".format(
            json.dumps(_pci_alias1, sort_keys=True),
            json.dumps(_pci_alias2, sort_keys=True))

        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'
        u.log.debug('Setting pci-alias to {}'.format(json.dumps(
            _pci_alias1,
            sort_keys=True)))
        self.d.configure(
            'nova-cloud-controller',
            {'pci-alias': json.dumps(_pci_alias1, sort_keys=True)})

        u.log.debug('Waiting for config change to take effect')
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

        u.log.debug('Setting pci-alias to {}'.format(_pci_alias_list))
        self.d.configure(
            'nova-cloud-controller',
            {'pci-alias': _pci_alias_list})
        u.log.debug('Waiting for config change to take effect')
        self.d.sentry.wait()

        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(unit.file_contents(conf))
        f.close()
        CONF(default_config_files=[f.name])
        if CompareOpenStackReleases(os_release) >= 'ocata':
            alias_entries = CONF.pci.alias
        else:
            alias_entries = CONF.DEFAULT.pci_alias
        assert alias_entries[0] == (
            '{"capability_type": "pci", "device_type": "type-PF", '
            '"name": "IntelNIC", "product_id": "1111", "vendor_id": "8086"}')
        assert alias_entries[1] == (
            '{"capability_type": "pci", "device_type": "type-PCI", '
            '"name": " Cirrus Logic ", "product_id": "0ff2", '
            '"vendor_id": "10de"}')
        self.d.configure('nova-cloud-controller', {'pci-alias': ''})
        self.d.sentry.wait()

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

    def test_500_security_checklist_action(self):
        """Verify expected result on a default install"""
        u.log.debug("Testing security-checklist")
        sentry_unit = self.nova_cc_sentry

        action_id = u.run_action(sentry_unit, "security-checklist")
        u.wait_on_action(action_id)
        data = amulet.actions.get_action_output(action_id, full_output=True)
        assert data.get(u"status") == "failed", \
            "Security check is expected to not pass by default"

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

        if cmp_os_release >= 'rocky':
            del services['nova-api-os-compute']
            services['apache2'] = conf_file

        if (self._get_openstack_release() >= self.xenial_ocata and
                self._get_openstack_release() <= self.disco_stein):
            # nova-placement-api is run under apache2 with mod_wsgi
            services['apache2'] = conf_file

        # Expected default and alternate values
        flags_default = 'cpu-allocation-ratio=16.0,ram-allocation-ratio=0.98'
        flags_alt = 'cpu-allocation-ratio=32.0,ram-allocation-ratio=3.0'
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

    def test_902_default_quota_settings(self):
        """Test default quota settings."""
        config_file = '/etc/nova/nova.conf'
        quotas = {
            'quota-instances': 20,
            'quota-cores': 40,
            'quota-ram': 102400,
            'quota-metadata-items': 256,
            'quota-injected-files': 10,
            'quota-injected-file-size': 20480,
            'quota-injected-path-size': 512,
            'quota-key-pairs': 200,
            'quota-server-groups': 20,
            'quota-server-group-members': 20,
        }
        cmp_os_release = CompareOpenStackReleases(
            self._get_openstack_release_string()
        )
        if cmp_os_release > 'newton':
            section = 'quota'
        else:
            section = 'DEFAULT'
        u.log.debug('Changing quotas in charm config')
        self.d.configure('nova-cloud-controller', quotas)
        self._auto_wait_for_status(exclude_services=self.exclude_services)
        self.d.sentry.wait()

        if not u.validate_config_data(self.nova_cc_sentry, config_file,
                                      section, quotas):
            amulet.raise_status(amulet.FAIL, msg='update failed')

        u.log.debug('New default quotas found in correct section in nova.conf')
        u.log.debug('test_902_default_quota_settings PASSED - (OK)')

        # Amulet test framework currently does not support setting charm-config
        # values to None when an integer is expected by the configuration.
        # By default, the quota settings are not written to nova.conf unless
        # explicitly set. In order to keep tests idempotent, the following juju
        # CLI commands are run to reset the quota values to None.
        os.system("juju config nova-cloud-controller --reset"
                  " quota-instances")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-cores")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-ram")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-metadata-items")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-injected-files")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-injected-file-size")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-injected-path-size")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-key-pairs")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-server-groups")
        os.system("juju config nova-cloud-controller --reset"
                  " quota-server-group-members")
        self._auto_wait_for_status(exclude_services=self.exclude_services)
