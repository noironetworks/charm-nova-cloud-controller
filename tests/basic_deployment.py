#!/usr/bin/python

import amulet
import os
import yaml

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG, # flake8: noqa
    ERROR
)

# Use DEBUG to turn on debug logging
u = OpenStackAmuletUtils(DEBUG)


class NovaCCBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic nova cloud controller deployment."""

    def __init__(self, series=None, openstack=None, source=None, git=False,
                 stable=False):
        """Deploy the entire test environment."""
        super(NovaCCBasicDeployment, self).__init__(series, openstack, source, stable)
        self.git = git
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()
        self._initialize_tests()

    def _add_services(self):
        """Add services

           Add the services that we're testing, where nova-cc is local,
           and the rest of the service are from lp branches that are
           compatible with the local charm (e.g. stable or next).
           """
        this_service = {'name': 'nova-cloud-controller'}
        other_services = [{'name': 'mysql'}, {'name': 'rabbitmq-server'},
                          {'name': 'nova-compute', 'units': 2},
                          {'name': 'keystone'}, {'name': 'glance'}]
        super(NovaCCBasicDeployment, self)._add_services(this_service,
                                                         other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
          'nova-cloud-controller:shared-db': 'mysql:shared-db',
          'nova-cloud-controller:identity-service': 'keystone:identity-service',
          'nova-cloud-controller:amqp': 'rabbitmq-server:amqp',
          'nova-cloud-controller:cloud-compute': 'nova-compute:cloud-compute',
          'nova-cloud-controller:image-service': 'glance:image-service',
          'nova-compute:image-service': 'glance:image-service',
          'nova-compute:shared-db': 'mysql:shared-db',
          'nova-compute:amqp': 'rabbitmq-server:amqp',
          'keystone:shared-db': 'mysql:shared-db',
          'glance:identity-service': 'keystone:identity-service',
          'glance:shared-db': 'mysql:shared-db',
          'glance:amqp': 'rabbitmq-server:amqp'
        }
        super(NovaCCBasicDeployment, self)._add_relations(relations)

    def _configure_services(self):
        """Configure all of the services."""
        nova_cc_config = {}
        if self.git:
            amulet_http_proxy = os.environ.get('AMULET_HTTP_PROXY')

            reqs_repo = 'git://github.com/openstack/requirements'
            nova_repo = 'git://github.com/openstack/nova'
            if self._get_openstack_release() == self.trusty_icehouse:
                reqs_repo = 'git://github.com/coreycb/requirements'

            release = self._get_openstack_release_string()
            reqs_branch = 'stable/' + release
            nova_branch = 'stable/' + release
            if self._get_openstack_release() == self.trusty_icehouse:
                nova_branch = release + '-eol'

            openstack_origin_git = {
                'repositories': [
                    {'name': 'requirements',
                     'repository': reqs_repo,
                     'branch': reqs_branch},
                    {'name': 'nova',
                     'repository': nova_repo,
                     'branch': nova_branch},
                ],
                'directory': '/mnt/openstack-git',
                'http_proxy': amulet_http_proxy,
                'https_proxy': amulet_http_proxy,
            }
            nova_cc_config['openstack-origin-git'] = yaml.dump(openstack_origin_git)
        keystone_config = {'admin-password': 'openstack',
                           'admin-token': 'ubuntutesting'}
        configs = {'nova-cloud-controller': nova_cc_config,
                   'keystone': keystone_config}
        super(NovaCCBasicDeployment, self)._configure_services(configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.mysql_sentry = self.d.sentry.unit['mysql/0']
        self.keystone_sentry = self.d.sentry.unit['keystone/0']
        self.rabbitmq_sentry = self.d.sentry.unit['rabbitmq-server/0']
        self.nova_cc_sentry = self.d.sentry.unit['nova-cloud-controller/0']
        self.nova_compute_sentry = self.d.sentry.unit['nova-compute/0']
        self.glance_sentry = self.d.sentry.unit['glance/0']

        # Authenticate admin with keystone
        self.keystone = u.authenticate_keystone_admin(self.keystone_sentry,
                                                      user='admin',
                                                      password='openstack',
                                                      tenant='admin')

        # Authenticate admin with glance endpoint
        self.glance = u.authenticate_glance_admin(self.keystone)

        # Create a demo tenant/role/user
        self.demo_tenant = 'demoTenant'
        self.demo_role = 'demoRole'
        self.demo_user = 'demoUser'
        if not u.tenant_exists(self.keystone, self.demo_tenant):
            tenant = self.keystone.tenants.create(tenant_name=self.demo_tenant,
                                                  description='demo tenant',
                                                  enabled=True)
            self.keystone.roles.create(name=self.demo_role)
            self.keystone.users.create(name=self.demo_user,
                                       password='password',
                                       tenant_id=tenant.id,
                                       email='demo@demo.com')

        # Authenticate demo user with keystone
        self.keystone_demo = \
            u.authenticate_keystone_user(self.keystone, user=self.demo_user,
                                         password='password',
                                         tenant=self.demo_tenant)

        # Authenticate demo user with nova-api
        self.nova_demo = u.authenticate_nova_user(self.keystone,
                                                  user=self.demo_user,
                                                  password='password',
                                                  tenant=self.demo_tenant)

    def test_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        commands = {
            self.mysql_sentry: ['status mysql'],
            self.rabbitmq_sentry: ['sudo service rabbitmq-server status'],
            self.nova_cc_sentry: ['status nova-api-ec2',
                                  'status nova-api-os-compute',
                                  'status nova-objectstore',
                                  'status nova-cert',
                                  'status nova-scheduler'],
            self.nova_compute_sentry: ['status nova-compute',
                                       'status nova-network',
                                       'status nova-api'],
            self.keystone_sentry: ['status keystone'],
            self.glance_sentry: ['status glance-registry', 'status glance-api']
        }
        if self._get_openstack_release() >= self.precise_grizzly:
            commands[self.nova_cc_sentry] = ['status nova-conductor']

        ret = u.validate_services(commands)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_service_catalog(self):
        """Verify that the service catalog endpoint data is valid."""
        endpoint_vol = {'adminURL': u.valid_url,
                        'region': 'RegionOne',
                        'publicURL': u.valid_url,
                        'internalURL': u.valid_url}
        endpoint_id = {'adminURL': u.valid_url,
                       'region': 'RegionOne',
                       'publicURL': u.valid_url,
                       'internalURL': u.valid_url}
        if self._get_openstack_release() >= self.precise_folsom:
            endpoint_vol['id'] = u.not_null
            endpoint_id['id'] = u.not_null
        expected = {'s3': [endpoint_vol], 'compute': [endpoint_vol],
                    'ec2': [endpoint_vol], 'identity': [endpoint_id]}
        actual = self.keystone_demo.service_catalog.get_endpoints()

        ret = u.validate_svc_catalog_endpoint_data(expected, actual)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_openstack_compute_api_endpoint(self):
        """Verify the openstack compute api (osapi) endpoint data."""
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8774'
        expected = {'id': u.not_null,
                    'region': 'RegionOne',
                    'adminurl': u.valid_url,
                    'internalurl': u.valid_url,
                    'publicurl': u.valid_url,
                    'service_id': u.not_null}

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'osapi endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_ec2_api_endpoint(self):
        """Verify the EC2 api endpoint data."""
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '8773'
        expected = {'id': u.not_null,
                    'region': 'RegionOne',
                    'adminurl': u.valid_url,
                    'internalurl': u.valid_url,
                    'publicurl': u.valid_url,
                    'service_id': u.not_null}

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'EC2 endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_s3_api_endpoint(self):
        """Verify the S3 api endpoint data."""
        endpoints = self.keystone.endpoints.list()
        admin_port = internal_port = public_port = '3333'
        expected = {'id': u.not_null,
                    'region': 'RegionOne',
                    'adminurl': u.valid_url,
                    'internalurl': u.valid_url,
                    'publicurl': u.valid_url,
                    'service_id': u.not_null}

        ret = u.validate_endpoint_data(endpoints, admin_port, internal_port,
                                       public_port, expected)
        if ret:
            message = 'S3 endpoint: {}'.format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_nova_cc_shared_db_relation(self):
        """Verify the nova-cc to mysql shared-db relation data"""
        unit = self.nova_cc_sentry
        relation = ['shared-db', 'mysql:shared-db']
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

    def test_mysql_shared_db_relation(self):
        """Verify the mysql to nova-cc shared-db relation data"""
        unit = self.mysql_sentry
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

    def test_nova_cc_identity_service_relation(self):
        """Verify the nova-cc to keystone identity-service relation data"""
        unit = self.nova_cc_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'nova_internal_url': u.valid_url,
            'nova_public_url': u.valid_url,
            's3_public_url': u.valid_url,
            's3_service': 's3',
            'ec2_admin_url': u.valid_url,
            'ec2_internal_url': u.valid_url,
            'nova_service': 'nova',
            's3_region': 'RegionOne',
            'private-address': u.valid_ip,
            'nova_region': 'RegionOne',
            'ec2_public_url': u.valid_url,
            'ec2_region': 'RegionOne',
            's3_internal_url': u.valid_url,
            's3_admin_url': u.valid_url,
            'nova_admin_url': u.valid_url,
            'ec2_service': 'ec2'
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_keystone_identity_service_relation(self):
        """Verify the keystone to nova-cc identity-service relation data"""
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
            'service_username': 's3_ec2_nova',
            'service_tenant_id': u.not_null,
            'service_host': u.valid_ip
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_nova_cc_amqp_relation(self):
        """Verify the nova-cc to rabbitmq-server amqp relation data"""
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

    def test_rabbitmq_amqp_relation(self):
        """Verify the rabbitmq-server to nova-cc amqp relation data"""
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

    def test_nova_cc_cloud_compute_relation(self):
        """Verify the nova-cc to nova-compute cloud-compute relation data"""
        unit = self.nova_cc_sentry
        relation = ['cloud-compute', 'nova-compute:cloud-compute']
        expected = {
            'volume_service': 'cinder',
            'network_manager': 'flatdhcpmanager',
            'ec2_host': u.valid_ip,
            'private-address': u.valid_ip,
            'restart_trigger': u.not_null
        }
        if self._get_openstack_release() == self.precise_essex:
            expected['volume_service'] = 'nova-volume'

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_nova_cloud_compute_relation(self):
        """Verify the nova-compute to nova-cc cloud-compute relation data"""
        unit = self.nova_compute_sentry
        relation = ['cloud-compute', 'nova-cloud-controller:cloud-compute']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-compute cloud-compute', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_nova_cc_image_service_relation(self):
        """Verify the nova-cc to glance image-service relation data"""
        unit = self.nova_cc_sentry
        relation = ['image-service', 'glance:image-service']
        expected = {
            'private-address': u.valid_ip,
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('nova-cc image-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_glance_image_service_relation(self):
        """Verify the glance to nova-cc image-service relation data"""
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

    def test_z_restart_on_config_change(self):
        """Verify that the specified services are restarted when the config
           is changed.

           Note(coreycb): The method name with the _z_ is a little odd
           but it forces the test to run last.  It just makes things
           easier because restarting services requires re-authorization.
           """
        # NOTE(coreycb): Skipping failing test on essex until resolved.
        #                config-flags don't take effect on essex.
        if self._get_openstack_release() == self.precise_essex:
            u.log.error("Skipping failing test until resolved")
            return

        flags_set = 'quota_cores=20,quota_instances=40,quota_ram=102400'
        flags_reset = 'quota_cores=10,quota_instances=20,quota_ram=51200'

        services = ['nova-api-ec2', 'nova-api-os-compute', 'nova-objectstore',
                    'nova-cert', 'nova-scheduler', 'nova-conductor']
        self.d.configure('nova-cloud-controller', {'config-flags': flags_set})
        pgrep_full = True

        time = 20
        conf = '/etc/nova/nova.conf'
        for s in services:
            if not u.service_restarted(self.nova_cc_sentry, s, conf,
                                       pgrep_full=True, sleep_time=time):
                self.d.configure('nova-cloud-controller',
                                 {'config-flags': flags_reset})
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)
            time = 0

        self.d.configure('nova-cloud-controller', {'config-flags': flags_reset})

    def test_nova_default_config(self):
        """Verify the data in the nova config file's default section."""
        # NOTE(coreycb): Currently no way to test on essex because config file
        #                has no section headers.
        if self._get_openstack_release() == self.precise_essex:
            return

        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'
        rabbitmq_relation = self.rabbitmq_sentry.relation('amqp',
                                                   'nova-cloud-controller:amqp')
        glance_relation = self.glance_sentry.relation('image-service',
                                          'nova-cloud-controller:image-service')
        keystone_ep = self.keystone_demo.service_catalog.url_for(\
                                                      service_type='identity',
                                                      endpoint_type='publicURL')
        keystone_ec2 = "{}/ec2tokens".format(keystone_ep)

        expected = {'dhcpbridge_flagfile': '/etc/nova/nova.conf',
                    'dhcpbridge': '/usr/bin/nova-dhcpbridge',
                    'logdir': '/var/log/nova',
                    'state_path': '/var/lib/nova',
                    'lock_path': '/var/lock/nova',
                    'force_dhcp_release': 'True',
                    'iscsi_helper': 'tgtadm',
                    'libvirt_use_virtio_for_bridges': 'True',
                    'connection_type': 'libvirt',
                    'root_helper': 'sudo nova-rootwrap /etc/nova/rootwrap.conf',
                    'verbose': 'False',
                    'debug': 'False',
                    'ec2_private_dns_show_ip': 'True',
                    'api_paste_config': '/etc/nova/api-paste.ini',
                    'volumes_path': '/var/lib/nova/volumes',
                    'enabled_apis': 'ec2,osapi_compute,metadata',
                    'auth_strategy': 'keystone',
                    'compute_driver': 'libvirt.LibvirtDriver',
                    'keystone_ec2_url': keystone_ec2,
                    'rabbit_userid': 'nova',
                    'rabbit_virtual_host': 'openstack',
                    'rabbit_password': rabbitmq_relation['password'],
                    'rabbit_host': rabbitmq_relation['hostname'],
                    'glance_api_servers': glance_relation['glance-api-server'],
                    'network_manager': 'nova.network.manager.FlatDHCPManager',
                    's3_listen_port': '3323',
                    'osapi_compute_listen_port': '8764',
                    'ec2_listen_port': '8763'}

        # This has been moved to [database] for I and above
        if self._get_openstack_release() < self.precise_icehouse:
            mysql_relation = self.mysql_sentry.relation('shared-db',
                                            'nova-cloud-controller:shared-db')
            db_uri = "mysql://{}:{}@{}/{}".format('nova',
                                              mysql_relation['nova_password'],
                                              mysql_relation['db_host'],
                                              'nova')
            expected['sql_connection'] = db_uri

        ret = u.validate_config_data(unit, conf, 'DEFAULT', expected)
        if ret:
            message = "nova config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_nova_database_config(self):
        """Verify the data in the nova config file's database section."""
        # NOTE(hopem): this is >= Icehouse only
        if self._get_openstack_release() < self.precise_icehouse:
            return

        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'
        mysql_relation = self.mysql_sentry.relation('shared-db',
                                              'nova-cloud-controller:shared-db')
        db_uri = "mysql://{}:{}@{}/{}".format('nova',
                                              mysql_relation['nova_password'],
                                              mysql_relation['db_host'],
                                              'nova')

        # For >= icehouse we move away from deprecated sql_connection
        expected = {'connection': db_uri}

        ret = u.validate_config_data(unit, conf, 'database', expected)
        if ret:
            message = "nova config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_nova_keystone_authtoken_config(self):
        """Verify the data in the nova config file's keystone_authtoken
           section. This data only exists since icehouse."""
        if self._get_openstack_release() < self.precise_icehouse:
            return

        unit = self.nova_cc_sentry
        conf = '/etc/nova/nova.conf'
        keystone_relation = self.keystone_sentry.relation('identity-service',
                                       'nova-cloud-controller:identity-service')
        keystone_uri = "http://{}:{}/".format(keystone_relation['service_host'],
                                              keystone_relation['service_port'])
        expected = {'auth_uri': keystone_uri,
                    'auth_host': keystone_relation['service_host'],
                    'auth_port': keystone_relation['auth_port'],
                    'auth_protocol': keystone_relation['auth_protocol'],
                    'admin_tenant_name': keystone_relation['service_tenant'],
                    'admin_user': keystone_relation['service_username'],
                    'admin_password': keystone_relation['service_password']}

        ret = u.validate_config_data(unit, conf, 'keystone_authtoken', expected)
        if ret:
            message = "nova config error: {}".format(ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_image_instance_create(self):
        """Create an image/instance, verify they exist, and delete them."""
        # NOTE(coreycb): Skipping failing test on essex until resolved. essex
        #                nova API calls are getting "Malformed request url (HTTP
        #                400)".
        if self._get_openstack_release() == self.precise_essex:
            u.log.error("Skipping failing test until resolved")
            return

        image = u.create_cirros_image(self.glance, "cirros-image")
        if not image:
            amulet.raise_status(amulet.FAIL, msg="Image create failed")

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

        u.delete_image(self.glance, image)
        u.delete_instance(self.nova_demo, instance)
