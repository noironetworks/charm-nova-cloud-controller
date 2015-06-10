from __future__ import print_function

import mock

#####
# NOTE(freyes): this is a workaround to patch config() function imported by
# nova_cc_utils before it gets a reference to the actual config() provided by
# hookenv module.
from charmhelpers.core import hookenv
_conf = hookenv.config
hookenv.config = mock.MagicMock()
import nova_cc_utils as _utils
# this assert is a double check + to avoid pep8 warning
assert _utils.config == hookenv.config
hookenv.config = _conf
#####

import nova_cc_context as context

from charmhelpers.contrib.openstack import utils

from test_utils import CharmTestCase


TO_PATCH = [
    'apt_install',
    'filter_installed_packages',
    'relation_ids',
    'relation_get',
    'related_units',
    'config',
    'log',
    'relations_for_id',
    'https',
]


def fake_log(msg, level=None):
    level = level or 'INFO'
    print('[juju test log (%s)] %s' % (level, msg))


class NovaComputeContextTests(CharmTestCase):
    def setUp(self):
        super(NovaComputeContextTests, self).setUp(context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get
        self.log.side_effect = fake_log

    @mock.patch.object(context, 'resolve_address',
                       lambda *args, **kwargs: None)
    @mock.patch.object(utils, 'os_release')
    @mock.patch('charmhelpers.contrib.network.ip.log')
    def test_instance_console_context_without_memcache(self, os_release, log_):
        self.relation_ids.return_value = 'cache:0'
        self.related_units.return_value = 'memcached/0'
        instance_console = context.InstanceConsoleContext()
        os_release.return_value = 'icehouse'
        self.assertEqual({'memcached_servers': ''},
                         instance_console())

    @mock.patch.object(context, 'resolve_address',
                       lambda *args, **kwargs: None)
    @mock.patch.object(utils, 'os_release')
    @mock.patch('charmhelpers.contrib.network.ip.log')
    def test_instance_console_context_with_memcache(self, os_release, log_):
        self.check_instance_console_context_with_memcache(os_release,
                                                          '127.0.1.1',
                                                          '127.0.1.1')

    @mock.patch.object(context, 'resolve_address',
                       lambda *args, **kwargs: None)
    @mock.patch.object(utils, 'os_release')
    @mock.patch('charmhelpers.contrib.network.ip.log')
    def test_instance_console_context_with_memcache_ipv6(self, os_release,
                                                         log_):
        self.check_instance_console_context_with_memcache(os_release, '::1',
                                                          '[::1]')

    def check_instance_console_context_with_memcache(self, os_release, ip,
                                                     formated_ip):
        memcached_servers = [{'private-address': formated_ip,
                              'port': '11211'}]
        self.relation_ids.return_value = ['cache:0']
        self.relations_for_id.return_value = memcached_servers
        self.related_units.return_value = 'memcached/0'
        instance_console = context.InstanceConsoleContext()
        os_release.return_value = 'icehouse'
        self.maxDiff = None
        self.assertEqual({'memcached_servers': "%s:11211" % (formated_ip, )},
                         instance_console())

    @mock.patch('charmhelpers.contrib.openstack.neutron.os_release')
    @mock.patch.object(context, 'use_local_neutron_api')
    @mock.patch('charmhelpers.contrib.openstack.ip.config')
    @mock.patch('charmhelpers.contrib.openstack.ip.is_clustered')
    def test_neutron_context_single_vip(self, mock_is_clustered, mock_config,
                                        mock_use_local_neutron_api,
                                        _os_release):
        mock_use_local_neutron_api.return_value = True
        self.https.return_value = False
        mock_is_clustered.return_value = True
        config = {'vip': '10.0.0.1',
                  'os-internal-network': '10.0.0.1/24',
                  'os-admin-network': '10.0.1.0/24',
                  'os-public-network': '10.0.2.0/24'}
        mock_config.side_effect = lambda key: config.get(key)

        mock_use_local_neutron_api.return_value = False
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.0.1:8774/v2')
        self.assertFalse('neutron_url' in ctxt)

        mock_use_local_neutron_api.return_value = True
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.0.1:8774/v2')
        self.assertEqual(ctxt['neutron_url'], 'http://10.0.0.1:9696')

    @mock.patch('charmhelpers.contrib.openstack.neutron.os_release')
    @mock.patch.object(context, 'use_local_neutron_api')
    @mock.patch('charmhelpers.contrib.openstack.ip.config')
    @mock.patch('charmhelpers.contrib.openstack.ip.is_clustered')
    def test_neutron_context_multi_vip(self, mock_is_clustered, mock_config,
                                       mock_use_local_neutron_api,
                                       _os_release):
        self.https.return_value = False
        mock_is_clustered.return_value = True
        config = {'vip': '10.0.0.1 10.0.1.1 10.0.2.1',
                  'os-internal-network': '10.0.1.0/24',
                  'os-admin-network': '10.0.0.0/24',
                  'os-public-network': '10.0.2.0/24'}
        mock_config.side_effect = lambda key: config.get(key)

        mock_use_local_neutron_api.return_value = False
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.1.1:8774/v2')
        self.assertFalse('neutron_url' in ctxt)

        mock_use_local_neutron_api.return_value = True
        ctxt = context.NeutronCCContext()()
        self.assertEqual(ctxt['nova_url'], 'http://10.0.1.1:8774/v2')
        self.assertEqual(ctxt['neutron_url'], 'http://10.0.1.1:9696')

    def test_use_local_neutron_api(self):
        self.relation_ids.return_value = []
        self.related_units.return_value = []
        self.assertTrue(context.use_local_neutron_api())
        self.relation_ids.return_value = ['rel:0']
        self.related_units.return_value = []
        self.assertTrue(context.use_local_neutron_api())
        self.related_units.return_value = ['unit/0']
        self.assertFalse(context.use_local_neutron_api())
