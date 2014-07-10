from mock import MagicMock, patch
from test_utils import CharmTestCase, patch_open
import os
with patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'neutron'
    import nova_cc_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import nova_cc_hooks as hooks

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    'api_port',
    'apt_update',
    'apt_install',
    'canonical_url',
    'configure_installation_source',
    'charm_dir',
    'do_openstack_upgrade',
    'openstack_upgrade_available',
    'config',
    'determine_packages',
    'determine_ports',
    'open_port',
    'is_relation_made',
    'log',
    'relation_get',
    'relation_set',
    'relation_ids',
    'ssh_compute_add',
    'ssh_known_hosts_b64',
    'ssh_authorized_keys_b64',
    'save_script_rc',
    'service_running',
    'service_stop',
    'execd_preinstall',
    'network_manager',
    'volume_service',
    'unit_get',
    'eligible_leader',
    'keystone_ca_cert_b64',
    'neutron_plugin',
    'migrate_database',
]


FAKE_KS_AUTH_CFG = {
    'auth_host': 'kshost',
    'auth_port': '5000',
    'service_port': 'token',
    'service_username': 'admin_user',
    'service_password': 'admin_passwd',
    'service_tenant_name': 'admin_tenant',
    'auth_uri': 'http://kshost:5000/v2',
    # quantum-gateway interface deviates a bit.
    'keystone_host': 'kshost',
    'service_tenant': 'service_tenant',
}


class NovaCCHooksTests(CharmTestCase):

    def setUp(self):
        super(NovaCCHooksTests, self).setUp(hooks, TO_PATCH)

        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get
        self.charm_dir.return_value = '/var/lib/juju/charms/nova/charm'

    def test_install_hook(self):
        self.determine_packages.return_value = [
            'nova-scheduler', 'nova-api-ec2']
        self.determine_ports.return_value = [80, 81, 82]
        hooks.install()
        self.apt_install.assert_called_with(
            ['nova-scheduler', 'nova-api-ec2'], fatal=True)
        self.execd_preinstall.assert_called()

    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade(self, conf_https):
        self.openstack_upgrade_available.return_value = False
        hooks.config_changed()
        self.assertTrue(self.save_script_rc.called)

    @patch.object(hooks, 'configure_https')
    def test_config_changed_with_upgrade(self, conf_https):
        self.openstack_upgrade_available.return_value = True
        hooks.config_changed()
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(self.save_script_rc.called)

    def test_compute_changed_ssh_migration(self):
        self.test_relation.set({
            'migration_auth_type': 'ssh', 'ssh_public_key': 'fookey',
            'private-address': '10.0.0.1'})
        self.ssh_known_hosts_b64.return_value = 'hosts'
        self.ssh_authorized_keys_b64.return_value = 'keys'
        hooks.compute_changed()
        self.ssh_compute_add.assert_called_with('fookey')
        self.relation_set.assert_called_with(known_hosts='hosts',
                                             authorized_keys='keys')

    @patch.object(utils, 'config')
    @patch.object(hooks, '_auth_config')
    def test_compute_joined_neutron(self, auth_config, _util_config):
        _util_config.return_value = 'none'
        self.is_relation_made.return_value = False
        self.network_manager.return_value = 'neutron'
        self.eligible_leader = True
        self.keystone_ca_cert_b64.return_value = 'foocert64'
        self.volume_service.return_value = 'cinder'
        self.unit_get.return_value = 'nova-cc-host1'
        self.canonical_url.return_value = 'http://nova-cc-host1'
        self.api_port.return_value = '9696'
        self.neutron_plugin.return_value = 'nvp'
        auth_config.return_value = FAKE_KS_AUTH_CFG
        hooks.compute_joined()

        self.relation_set.assert_called_with(
            relation_id=None,
            quantum_url='http://nova-cc-host1:9696',
            ca_cert='foocert64',
            quantum_port=9696,
            quantum_host='nova-cc-host1',
            quantum_security_groups='no',
            region='RegionOne',
            volume_service='cinder',
            ec2_host='nova-cc-host1',
            quantum_plugin='nvp',
            network_manager='neutron', **FAKE_KS_AUTH_CFG)

    @patch.object(utils, 'config')
    @patch.object(hooks, 'NeutronAPIContext')
    @patch.object(hooks, '_auth_config')
    def test_compute_joined_neutron_api_rel(self, auth_config, napi,
                                            _util_config):
        def mock_NeutronAPIContext():
            return {
                'neutron_plugin': 'bob',
                'neutron_security_groups': 'yes',
                'neutron_url': 'http://nova-cc-host1:9696',
            }
        _util_config.return_value = 'none'
        napi.return_value = mock_NeutronAPIContext
        self.is_relation_made.return_value = True
        self.network_manager.return_value = 'neutron'
        self.eligible_leader = True
        self.keystone_ca_cert_b64.return_value = 'foocert64'
        self.volume_service.return_value = 'cinder'
        self.unit_get.return_value = 'nova-cc-host1'
        self.canonical_url.return_value = 'http://nova-cc-host1'
        self.api_port.return_value = '9696'
        self.neutron_plugin.return_value = 'nvp'
        auth_config.return_value = FAKE_KS_AUTH_CFG
        hooks.compute_joined()
        self.relation_set.assert_called_with(
            relation_id=None,
            quantum_url='http://nova-cc-host1:9696',
            ca_cert='foocert64',
            quantum_port=9696,
            quantum_host='nova-cc-host1',
            quantum_security_groups='yes',
            region='RegionOne',
            volume_service='cinder',
            ec2_host='nova-cc-host1',
            quantum_plugin='bob',
            network_manager='neutron', **FAKE_KS_AUTH_CFG)

    @patch.object(hooks, '_auth_config')
    def test_nova_vmware_joined(self, auth_config):
        auth_config.return_value = FAKE_KS_AUTH_CFG
        # quantum-security-groups, plugin
        self.neutron_plugin.return_value = 'nvp'
        self.network_manager.return_value = 'neutron'
        self.canonical_url.return_value = 'http://nova-cc-host1'
        self.api_port.return_value = '9696'
        hooks.nova_vmware_relation_joined()
        self.relation_set.assert_called_with(
            network_manager='neutron', quantum_security_groups='no',
            quantum_url='http://nova-cc-host1:9696', quantum_plugin='nvp',
            relation_id=None,
            **FAKE_KS_AUTH_CFG)

    def test_db_joined(self):
        self.unit_get.return_value = 'nova.foohost.com'
        self.is_relation_made.return_value = False
        hooks.db_joined()
        self.relation_set.assert_called_with(nova_database='nova',
                                             nova_username='nova',
                                             nova_hostname='nova.foohost.com')
        self.unit_get.assert_called_with('private-address')

    def test_postgresql_nova_db_joined(self):
        self.is_relation_made.return_value = False
        hooks.pgsql_nova_db_joined()
        self.relation_set.assert_called_with(database='nova')

    def test_postgresql_neutron_db_joined(self):
        self.is_relation_made.return_value = False
        hooks.pgsql_neutron_db_joined()
        self.relation_set.assert_called_with(database='neutron')

    def test_db_joined_with_postgresql(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a mysql database when'
                         ' there is already associated a postgresql one')

    def test_postgresql_nova_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_nova_db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a postgresql database when'
                         ' there is already associated a mysql one')

    def test_postgresql_neutron_joined_with_db(self):
        self.is_relation_made.return_value = True

        with self.assertRaises(Exception) as context:
            hooks.pgsql_neutron_db_joined()
        self.assertEqual(context.exception.message,
                         'Attempting to associate a postgresql database when'
                         ' there is already associated a mysql one')

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_nova_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.postgresql_nova_db_changed()
        self.log.assert_called_with(
            'pgsql-nova-db relation incomplete. Peer not ready?'
        )

    def _shared_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    def _postgresql_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['pgsql-nova-db']
        configs.write = MagicMock()
        hooks.postgresql_nova_db_changed()

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed(self, configs):
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.migrate_database.assert_called_with()

    @patch.object(hooks, 'CONFIGS')
    def test_postgresql_db_changed(self, configs):
        self._postgresql_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.migrate_database.assert_called_with()

    @patch.object(os, 'rename')
    @patch.object(os.path, 'isfile')
    @patch.object(hooks, 'CONFIGS')
    def test_neutron_api_relation_joined(self, configs, isfile, rename):
        neutron_conf = '/etc/neutron/neutron.conf'
        nova_url = 'http://novaurl:8774/v2'
        isfile.return_value = True
        self.service_running.return_value = True
        _identity_joined = self.patch('identity_joined')
        self.relation_ids.side_effect = ['relid']
        self.canonical_url.return_value = 'http://novaurl'
        with patch_open() as (_open, _file):
            hooks.neutron_api_relation_joined()
            self.service_stop.assert_called_with('neutron-server')
            rename.assert_called_with(neutron_conf, neutron_conf + '_unused')
            self.assertTrue(_identity_joined.called)
            self.relation_set.assert_called_with(relation_id=None,
                                                 nova_url=nova_url)

    @patch.object(hooks, 'CONFIGS')
    def test_neutron_api_relation_changed(self, configs):
        self.relation_ids.return_value = ['relid']
        _compute_joined = self.patch('compute_joined')
        _quantum_joined = self.patch('quantum_joined')
        hooks.neutron_api_relation_changed()
        self.assertTrue(configs.write.called_with('/etc/nova/nova.conf'))
        self.assertTrue(_compute_joined.called)
        self.assertTrue(_quantum_joined.called)

    @patch.object(os, 'remove')
    @patch.object(os.path, 'isfile')
    @patch.object(hooks, 'CONFIGS')
    def test_neutron_api_relation_broken(self, configs, isfile, remove):
        isfile.return_value = True
        self.relation_ids.return_value = ['relid']
        _compute_joined = self.patch('compute_joined')
        _quantum_joined = self.patch('quantum_joined')
        hooks.neutron_api_relation_broken()
        remove.assert_called_with('/etc/init/neutron-server.override')
        self.assertTrue(configs.write_all.called)
        self.assertTrue(_compute_joined.called)
        self.assertTrue(_quantum_joined.called)

    @patch.object(utils, 'config')
    def test_console_settings_vnc(self, _utils_config):
        _utils_config.return_value = 'vnc'
        _cc_host = "nova-cc-host1"
        self.canonical_url.return_value = 'http://' + _cc_host
        _con_sets = hooks.console_settings()
        console_settings = {
            'console_proxy_novnc_address': 'http://%s:6080/vnc_auto.html' %
                                           (_cc_host),
            'console_proxy_novnc_port': 6080,
            'console_access_protocol': 'vnc',
            'console_proxy_novnc_host': _cc_host,
            'console_proxy_xvpvnc_port': 6081,
            'console_proxy_xvpvnc_host': _cc_host,
            'console_proxy_xvpvnc_address': 'http://%s:6081/console' %
                                            (_cc_host),
            'console_keymap': 'en-us'
        }
        self.assertEqual(_con_sets, console_settings)

    @patch.object(utils, 'config')
    def test_console_settings_xvpvnc(self, _utils_config):
        _utils_config.return_value = 'xvpvnc'
        _cc_host = "nova-cc-host1"
        self.canonical_url.return_value = 'http://' + _cc_host
        _con_sets = hooks.console_settings()
        console_settings = {
            'console_access_protocol': 'xvpvnc',
            'console_keymap': 'en-us',
            'console_proxy_xvpvnc_port': 6081,
            'console_proxy_xvpvnc_host': _cc_host,
            'console_proxy_xvpvnc_address': 'http://%s:6081/console' %
                                            (_cc_host),
        }
        self.assertEqual(_con_sets, console_settings)

    @patch.object(utils, 'config')
    def test_console_settings_novnc(self, _utils_config):
        _utils_config.return_value = 'novnc'
        _cc_host = "nova-cc-host1"
        self.canonical_url.return_value = 'http://' + _cc_host
        _con_sets = hooks.console_settings()
        console_settings = {
            'console_proxy_novnc_address': 'http://%s:6080/vnc_auto.html' %
                                           (_cc_host),
            'console_proxy_novnc_port': 6080,
            'console_access_protocol': 'novnc',
            'console_proxy_novnc_host': _cc_host,
            'console_keymap': 'en-us'
        }
        self.assertEqual(_con_sets, console_settings)

    @patch.object(utils, 'config')
    def test_console_settings_spice(self, _utils_config):
        _utils_config.return_value = 'spice'
        _cc_host = "nova-cc-host1"
        self.canonical_url.return_value = 'http://' + _cc_host
        _con_sets = hooks.console_settings()
        console_settings = {
            'console_proxy_spice_address': 'http://%s:6082/spice_auto.html' %
                                           (_cc_host),
            'console_proxy_spice_host': _cc_host,
            'console_proxy_spice_port': 6082,
            'console_access_protocol': 'spice',
            'console_keymap': 'en-us'
        }
        self.assertEqual(_con_sets, console_settings)

    @patch.object(utils, 'config')
    def test_console_settings_explicit_ip(self, _utils_config):
        _utils_config.return_value = 'spice'
        _cc_public_host = "public-host"
        _cc_private_host = "private-host"
        self.test_config.set('console-proxy-ip', _cc_public_host)
        _con_sets = hooks.console_settings()
        self.canonical_url.return_value = 'http://' + _cc_private_host
        console_settings = {
            'console_proxy_spice_address': 'http://%s:6082/spice_auto.html' %
                                           (_cc_public_host),
            'console_proxy_spice_host': _cc_public_host,
            'console_proxy_spice_port': 6082,
            'console_access_protocol': 'spice',
            'console_keymap': 'en-us'
        }
        self.assertEqual(_con_sets, console_settings)
