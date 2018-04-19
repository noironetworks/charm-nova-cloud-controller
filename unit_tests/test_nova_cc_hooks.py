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

import os
import tempfile

from mock import MagicMock, patch, call
from test_utils import CharmTestCase

with patch('charmhelpers.core.hookenv.config') as config:
    with patch('charmhelpers.contrib.openstack.utils.get_os_codename_package'):
        config.return_value = 'neutron'
        import nova_cc_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    with patch('nova_cc_utils.guard_map') as gmap:
        with patch('charmhelpers.core.hookenv.config') as config:
            config.return_value = False
            gmap.return_value = {}
            import nova_cc_hooks as hooks

utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
    'apt_update',
    'apt_install',
    'configure_installation_source',
    'charm_dir',
    'do_openstack_upgrade',
    'openstack_upgrade_available',
    'config',
    'config_value_changed',
    'determine_endpoints',
    'determine_packages',
    'determine_ports',
    'NovaCellContext',
    'open_port',
    'is_relation_made',
    'is_unit_paused_set',
    'local_unit',
    'log',
    'os_release',
    'related_units',
    'relation_get',
    'relation_set',
    'relation_ids',
    'placement_api_enabled',
    'ssh_compute_add',
    'ssh_known_hosts_lines',
    'ssh_authorized_keys_lines',
    'save_script_rc',
    'service_pause',
    'service_reload',
    'service_resume',
    'services',
    'execd_preinstall',
    'network_manager',
    'unit_get',
    'uuid',
    'is_leader',
    'keystone_ca_cert_b64',
    'migrate_nova_databases',
    'uuid',
    'get_hacluster_config',
    'get_iface_for_address',
    'get_netmask_for_address',
    'update_nrpe_config',
    'status_set',
    'update_dns_ha_resource_params',
    'serial_console_settings',
    'get_relation_ip',
    'is_clustered',
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
        (tmpfd, hooks.NOVA_CONSOLEAUTH_OVERRIDE) = tempfile.mkstemp()

        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get
        self.charm_dir.return_value = '/var/lib/juju/charms/nova/charm'

    def tearDown(self):
        try:
            os.remove(hooks.NOVA_CONSOLEAUTH_OVERRIDE)
        except OSError:
            pass

        super(NovaCCHooksTests, self).tearDown()

    def test_install_hook(self):
        self.determine_packages.return_value = [
            'nova-scheduler', 'nova-api-ec2']
        self.determine_ports.return_value = [80, 81, 82]
        self.is_unit_paused_set.return_value = False
        self.services.return_value = ['dummy-service']
        hooks.install()
        self.apt_install.assert_called_with(
            ['nova-scheduler', 'nova-api-ec2'], fatal=True)
        self.assertTrue(self.execd_preinstall.called)
        self.assertTrue(self.service_pause.called)

    @patch.object(hooks, 'update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'determine_packages')
    @patch.object(utils, 'service_resume')
    @patch.object(utils, 'config')
    @patch.object(hooks, 'filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade(self, conf_https, mock_filter_packages,
                                       utils_config, mock_service_resume,
                                       mock_determine_packages,
                                       mock_is_db_initialised,
                                       mock_update_nova_consoleauth_config,
                                       mock_update_aws_compat_services):
        mock_determine_packages.return_value = []
        utils_config.side_effect = self.test_config.get
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.config_changed()
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_config.called)
        self.assertTrue(mock_update_aws_compat_services.called)

    @patch.object(hooks, 'update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'determine_packages')
    @patch.object(utils, 'service_resume')
    @patch.object(utils, 'config')
    @patch.object(hooks, 'filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_juno(self, conf_https,
                                            mock_filter_packages,
                                            utils_config, mock_service_resume,
                                            mock_determine_packages,
                                            mock_is_db_initialised,
                                            mock_update_nova_consoleauth_cfg,
                                            mock_update_aws_compat_services):
        mock_determine_packages.return_value = []
        utils_config.side_effect = self.test_config.get
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'juno'
        hooks.config_changed()
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_cfg.called)
        self.assertTrue(mock_update_aws_compat_services.called)
        self.service_pause.assert_called_with('neutron-server')

    @patch.object(hooks, 'update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'determine_packages')
    @patch.object(utils, 'service_resume')
    @patch.object(utils, 'config')
    @patch.object(hooks, 'filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_juno_no_neutron_server(
            self, conf_https, mock_filter_packages,
            utils_config, mock_service_resume,
            mock_determine_packages,
            mock_is_db_initialised,
            mock_update_nova_consoleauth_cfg,
            mock_update_aws_compat_services):
        mock_determine_packages.return_value = []
        utils_config.side_effect = self.test_config.get
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'juno'
        self.service_pause.side_effect = ValueError
        hooks.config_changed()
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_cfg.called)
        self.assertTrue(mock_update_aws_compat_services.called)
        self.service_pause.assert_called_with('neutron-server')

    @patch.object(hooks, 'update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'quantum_joined')
    @patch.object(hooks, 'determine_packages')
    @patch.object(utils, 'service_resume')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch.object(utils, 'config')
    @patch.object(hooks, 'db_joined')
    @patch.object(hooks, 'filter_installed_packages')
    @patch('charmhelpers.contrib.openstack.ip.service_name',
           lambda *args: 'nova-cloud-controller')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(hooks, 'identity_joined')
    @patch.object(hooks, 'neutron_api_relation_joined')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_with_upgrade(self, conf_https, neutron_api_joined,
                                         identity_joined, cluster_joined,
                                         mock_filter_packages, db_joined,
                                         utils_config, mock_relids,
                                         mock_unit_get,
                                         mock_service_resume,
                                         mock_determine_packages,
                                         mock_quantum_joined,
                                         mock_is_db_initialised,
                                         mock_update_nova_consoleauth_config,
                                         mock_update_aws_compat_services):
        mock_determine_packages.return_value = []
        mock_is_db_initialised.return_value = False
        self.openstack_upgrade_available.return_value = True
        self.relation_ids.return_value = ['generic_rid']
        utils_config.side_effect = self.test_config.get
        self.test_config.set('console-access-protocol', 'dummy')
        mock_relids.return_value = []
        mock_unit_get.return_value = '127.0.0.1'
        self.os_release.return_value = 'diablo'
        hooks.config_changed()
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(neutron_api_joined.called)
        self.assertTrue(identity_joined.called)
        self.assertTrue(cluster_joined.called)
        self.assertTrue(db_joined.called)
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_quantum_joined.called)
        self.assertTrue(mock_update_nova_consoleauth_config.called)
        self.assertTrue(mock_update_aws_compat_services.called)

    @patch.object(hooks, 'update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(utils, 'service_resume')
    @patch.object(hooks, 'filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'compute_changed')
    def test_config_changed_region_change(self, mock_compute_changed,
                                          mock_config_https,
                                          mock_filter_packages,
                                          mock_service_resume,
                                          mock_is_db_initialised,
                                          mock_update_nova_consoleauth_config,
                                          mock_update_aws_compat_services):
        self.openstack_upgrade_available.return_value = False
        self.config_value_changed.return_value = True
        self.related_units.return_value = ['unit/0']
        self.relation_ids.side_effect = \
            lambda x: ['generic_rid'] if x == 'cloud-compute' else []
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.config_changed()
        mock_compute_changed.assert_has_calls([call('generic_rid', 'unit/0')])
        self.assertTrue(mock_update_nova_consoleauth_config.called)
        self.assertTrue(mock_update_aws_compat_services.called)

    @patch.object(hooks, 'is_cellv2_init_ready')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'nova_api_relation_joined')
    def test_compute_changed_nova_api_trigger(self, api_joined,
                                              mock_is_db_initialised,
                                              mock_is_cellv2_init_ready):
        self.relation_ids.return_value = ['nova-api/0']
        mock_is_db_initialised.return_value = False
        mock_is_cellv2_init_ready.return_value = False
        hooks.compute_changed()
        api_joined.assert_called_with(rid='nova-api/0')

    @patch.object(hooks, 'is_cellv2_init_ready')
    @patch.object(hooks, 'is_db_initialised')
    def test_compute_changed_ssh_migration(self, mock_is_db_initialised,
                                           mock_is_cellv2_init_ready):
        self.test_relation.set({
            'migration_auth_type': 'ssh', 'ssh_public_key': 'fookey',
            'private-address': '10.0.0.1', 'region': 'RegionOne'})
        self.ssh_known_hosts_lines.return_value = [
            'k_h_0', 'k_h_1', 'k_h_2']
        self.ssh_authorized_keys_lines.return_value = [
            'auth_0', 'auth_1', 'auth_2']
        mock_is_db_initialised.return_value = False
        mock_is_cellv2_init_ready.return_value = False
        hooks.compute_changed()
        self.ssh_compute_add.assert_called_with('fookey', rid=None, unit=None)
        expected_relations = [
            call(relation_settings={'authorized_keys_0': 'auth_0'},
                 relation_id=None),
            call(relation_settings={'authorized_keys_1': 'auth_1'},
                 relation_id=None),
            call(relation_settings={'authorized_keys_2': 'auth_2'},
                 relation_id=None),
            call(relation_settings={'known_hosts_0': 'k_h_0'},
                 relation_id=None),
            call(relation_settings={'known_hosts_1': 'k_h_1'},
                 relation_id=None),
            call(relation_settings={'known_hosts_2': 'k_h_2'},
                 relation_id=None),
            call(authorized_keys_max_index=3, relation_id=None),
            call(known_hosts_max_index=3, relation_id=None)]
        self.assertEqual(sorted(self.relation_set.call_args_list),
                         sorted(expected_relations))

    @patch.object(hooks, 'is_cellv2_init_ready')
    @patch.object(hooks, 'is_db_initialised')
    def test_compute_changed_nova_public_key(self, mock_is_db_initialised,
                                             mock_is_cellv2_init_ready):
        self.test_relation.set({
            'migration_auth_type': 'sasl', 'nova_ssh_public_key': 'fookey',
            'private-address': '10.0.0.1', 'region': 'RegionOne'})
        self.ssh_known_hosts_lines.return_value = [
            'k_h_0', 'k_h_1', 'k_h_2']
        self.ssh_authorized_keys_lines.return_value = [
            'auth_0', 'auth_1', 'auth_2']
        mock_is_db_initialised.return_value = False
        mock_is_cellv2_init_ready.return_value = False
        hooks.compute_changed()
        self.ssh_compute_add.assert_called_with('fookey', user='nova',
                                                rid=None, unit=None)
        expected_relations = [
            call(relation_settings={'nova_authorized_keys_0': 'auth_0'},
                 relation_id=None),
            call(relation_settings={'nova_authorized_keys_1': 'auth_1'},
                 relation_id=None),
            call(relation_settings={'nova_authorized_keys_2': 'auth_2'},
                 relation_id=None),
            call(relation_settings={'nova_known_hosts_0': 'k_h_0'},
                 relation_id=None),
            call(relation_settings={'nova_known_hosts_1': 'k_h_1'},
                 relation_id=None),
            call(relation_settings={'nova_known_hosts_2': 'k_h_2'},
                 relation_id=None),
            call(relation_settings={'nova_known_hosts_max_index': 3},
                 relation_id=None),
            call(relation_settings={'nova_authorized_keys_max_index': 3},
                 relation_id=None)]
        self.assertEqual(sorted(self.relation_set.call_args_list),
                         sorted(expected_relations))

    @patch.object(hooks, 'is_cellv2_init_ready')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'add_hosts_to_cell')
    def test_compute_changed_add_hosts_leader(self,
                                              mock_add_hosts_to_cell,
                                              mock_is_db_initialised,
                                              mock_is_cellv2_init_ready):
        self.is_leader.return_value = True
        mock_is_db_initialised.return_value = True
        mock_is_cellv2_init_ready.return_value = True
        hooks.compute_changed()
        self.assertTrue(self.is_leader.called)
        self.assertTrue(mock_is_db_initialised.called)
        self.assertTrue(mock_is_cellv2_init_ready.called)
        self.assertTrue(mock_add_hosts_to_cell.called)

    @patch.object(hooks, 'is_cellv2_init_ready')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'add_hosts_to_cell')
    def test_compute_changed_add_hosts_nonleader(self,
                                                 mock_add_hosts_to_cell,
                                                 mock_is_db_initialised,
                                                 mock_is_cellv2_init_ready):
        self.is_leader.return_value = False
        mock_is_db_initialised.return_value = True
        mock_is_cellv2_init_ready.return_value = True
        hooks.compute_changed()
        self.assertTrue(self.is_leader.called)
        self.assertFalse(mock_is_db_initialised.called)
        self.assertFalse(mock_is_cellv2_init_ready.called)
        self.assertFalse(mock_add_hosts_to_cell.called)

    @patch.object(hooks, 'canonical_url')
    @patch.object(utils, 'config')
    @patch.object(hooks, '_auth_config')
    def test_compute_joined_neutron(self, auth_config, _util_config,
                                    _canonical_url):
        _util_config.return_value = None
        self.is_relation_made.return_value = False
        self.network_manager.return_value = 'neutron'
        self.is_leader = True
        self.keystone_ca_cert_b64.return_value = 'foocert64'
        self.unit_get.return_value = 'nova-cc-host1'
        self.serial_console_settings.return_value = {
            'enable_serial_console': 'false',
            'serial_console_base_url': 'ws://controller:6803',
        }
        _canonical_url.return_value = 'http://nova-cc-host1'
        auth_config.return_value = FAKE_KS_AUTH_CFG
        hooks.compute_joined()

        self.relation_set.assert_called_with(
            relation_id=None,
            ca_cert='foocert64',
            region='RegionOne',
            volume_service='cinder',
            ec2_host='nova-cc-host1',
            network_manager='neutron',
            enable_serial_console='false',
            serial_console_base_url='ws://controller:6803',
            **FAKE_KS_AUTH_CFG)

    @patch.object(hooks, 'canonical_url')
    @patch.object(utils, 'config')
    @patch.object(hooks, 'NeutronAPIContext')
    @patch.object(hooks, '_auth_config')
    def test_compute_joined_neutron_api_rel(self, auth_config, napi,
                                            _util_config, _canonical_url):
        def mock_NeutronAPIContext():
            return {
                'neutron_plugin': 'bob',
                'neutron_security_groups': 'yes',
                'neutron_url': 'http://nova-cc-host1:9696',
            }
        _util_config.return_value = None
        napi.return_value = mock_NeutronAPIContext
        self.is_relation_made.return_value = True
        self.network_manager.return_value = 'neutron'
        self.is_leader = True
        self.keystone_ca_cert_b64.return_value = 'foocert64'
        self.unit_get.return_value = 'nova-cc-host1'
        self.serial_console_settings.return_value = {
            'enable_serial_console': 'false',
            'serial_console_base_url': 'ws://controller:6803',
        }
        _canonical_url.return_value = 'http://nova-cc-host1'
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
            network_manager='neutron',
            enable_serial_console='false',
            serial_console_base_url='ws://controller:6803',
            **FAKE_KS_AUTH_CFG)

    @patch.object(hooks, 'canonical_url')
    @patch.object(hooks, '_auth_config')
    def test_nova_vmware_joined(self, auth_config, _canonical_url):
        auth_config.return_value = FAKE_KS_AUTH_CFG
        self.is_relation_made.return_value = False
        self.network_manager.return_value = 'neutron'
        _canonical_url.return_value = 'http://nova-cc-host1'
        hooks.nova_vmware_relation_joined()
        self.relation_set.assert_called_with(
            network_manager='neutron',
            relation_id=None,
            **FAKE_KS_AUTH_CFG)

    def test_db_joined(self):
        self.get_relation_ip.return_value = '10.10.10.10'
        self.is_relation_made.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.db_joined()
        self.relation_set.assert_called_with(nova_database='nova',
                                             nova_username='nova',
                                             nova_hostname='10.10.10.10',
                                             relation_id=None)
        self.get_relation_ip.assert_called_with('shared-db',
                                                cidr_network=None)

    def test_db_joined_spaces(self):
        self.get_relation_ip.return_value = '192.168.20.1'
        self.unit_get.return_value = 'nova.foohost.com'
        self.is_relation_made.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.db_joined()
        self.relation_set.assert_called_with(nova_database='nova',
                                             nova_username='nova',
                                             nova_hostname='192.168.20.1',
                                             relation_id=None)

    def test_db_joined_mitaka(self):
        self.get_relation_ip.return_value = '10.10.10.10'
        self.os_release.return_value = 'mitaka'
        self.is_relation_made.return_value = False
        hooks.db_joined()
        self.relation_set.assert_has_calls([
            call(nova_database='nova',
                 nova_username='nova',
                 nova_hostname='10.10.10.10',
                 relation_id=None),
            call(novaapi_database='nova_api',
                 novaapi_username='nova',
                 novaapi_hostname='10.10.10.10',
                 relation_id=None),
        ])

        self.get_relation_ip.assert_called_with('shared-db',
                                                cidr_network=None)

    @patch('charmhelpers.contrib.openstack.ip.service_name',
           lambda *args: 'nova-cloud-controller')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    @patch('charmhelpers.contrib.openstack.ip.config')
    def test_identity_joined(self, _ip_config, _is_clustered, _unit_get):
        _is_clustered.return_value = False
        _unit_get.return_value = '127.0.0.1'
        _ip_config.side_effect = self.test_config.get

        self.test_config.set('os-public-hostname', 'ncc.example.com')
        hooks.identity_joined()

        self.determine_endpoints.asssert_called_with(
            public_url='http://ncc.example.com',
            internal_url='http://127.0.0.1',
            admin_url='http://127.0.0.1'
        )

    def test_identity_joined_partial_cluster(self):
        self.is_clustered.return_value = False
        self.test_config.set('vip', '10.0.0.10')
        hooks.identity_joined()
        self.assertFalse(self.relation_set.called)

    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = []
        hooks.db_changed()
        self.log.assert_called_with(
            'shared-db relation incomplete. Peer not ready?'
        )

    def _shared_db_test(self, configs):
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['shared-db']
        configs.write = MagicMock()
        hooks.db_changed()

    @patch.object(hooks, 'nova_api_relation_joined')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed(self, configs,
                        mock_is_db_initialised, api_joined):
        self.relation_ids.return_value = ['nova-api/0']
        mock_is_db_initialised.return_value = False
        'No database migration is attempted when ACL list is not present'
        self.os_release.return_value = 'diablo'
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.assertFalse(self.migrate_nova_databases.called)
        api_joined.asert_called_with(rid='nova-api/0')

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_allowed(self, configs, mock_is_db_initialised,
                                utils_os_release, utils_is_leader):
        mock_is_db_initialised.return_value = False
        allowed_units = 'nova-cloud-controller/0 nova-cloud-controller/3'
        self.test_relation.set({
            'nova_allowed_units': allowed_units,
        })
        self.local_unit.return_value = 'nova-cloud-controller/3'
        self.os_release.return_value = 'diablo'
        utils_os_release.return_value = 'diablo'
        utils_is_leader.return_value = False
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.migrate_nova_databases.assert_called_with()

    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_not_allowed(self, configs, mock_is_db_initialised):
        mock_is_db_initialised.return_value = False
        allowed_units = 'nova-cloud-controller/0 nova-cloud-controller/3'
        self.test_relation.set({
            'nova_allowed_units': allowed_units,
        })
        self.local_unit.return_value = 'nova-cloud-controller/1'
        self.os_release.return_value = 'diablo'
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.assertFalse(self.migrate_nova_databases.called)

    @patch.object(utils, 'is_leader')
    @patch.object(utils, 'os_release')
    @patch.object(hooks, 'quantum_joined')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'nova_cell_relation_joined')
    @patch.object(hooks, 'compute_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_remote_restarts(self, configs, comp_joined,
                                        cell_joined, mock_is_db_initialised,
                                        quantum_joined, utils_os_release,
                                        utils_is_leader):
        mock_is_db_initialised.return_value = False

        def _relation_ids(rel):
            relid = {
                'cloud-compute': ['nova-compute/0'],
                'cell': ['nova-cell-api/0'],
                'neutron-api': ['neutron-api/0'],
                'quantum-network-service': ['neutron-gateway/0']
            }
            return relid[rel]
        self.relation_ids.side_effect = _relation_ids
        allowed_units = 'nova-cloud-controller/0'
        self.test_relation.set({
            'nova_allowed_units': allowed_units,
        })
        self.local_unit.return_value = 'nova-cloud-controller/0'
        self.os_release.return_value = 'diablo'
        utils_os_release.return_value = 'diablo'
        utils_is_leader.return_value = False
        self._shared_db_test(configs)
        comp_joined.assert_called_with(remote_restart=True,
                                       rid='nova-compute/0')
        cell_joined.assert_called_with(remote_restart=True,
                                       rid='nova-cell-api/0')
        quantum_joined.assert_called_with(remote_restart=True,
                                          rid='neutron-gateway/0')
        self.migrate_nova_databases.assert_called_with()

    @patch.object(hooks, 'nova_cell_relation_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_amqp_relation_broken(self, configs, cell_joined):
        configs.write = MagicMock()
        self.relation_ids.return_value = ['nova-cell-api/0']
        hooks.relation_broken()
        self.assertTrue(configs.write_all.called)
        cell_joined.assert_called_with(rid='nova-cell-api/0')

    @patch.object(hooks, 'leader_init_db_if_ready_allowed_units')
    @patch.object(hooks, 'update_cell_db_if_ready_allowed_units')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'quantum_joined')
    @patch.object(hooks, 'nova_api_relation_joined')
    @patch.object(hooks, 'nova_cell_relation_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_api_rel(self, configs, cell_joined, api_joined,
                                  quantum_joined, mock_is_db_initialised,
                                  update_db_allowed, init_db_allowed):
        self.relation_ids.side_effect = [
            ['nova-cell-api/0'],
            ['nova-api/0'],
            ['quantum-service/0'],
        ]
        mock_is_db_initialised.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['amqp']
        configs.write = MagicMock()
        self.os_release.return_value = 'diablo'
        self.is_relation_made.return_value = True
        hooks.amqp_changed()
        self.assertEqual(configs.write.call_args_list,
                         [call('/etc/nova/nova.conf')])
        cell_joined.assert_called_with(rid='nova-cell-api/0')
        api_joined.assert_called_with(rid='nova-api/0')
        quantum_joined.assert_called_with(rid='quantum-service/0',
                                          remote_restart=True)

    @patch.object(hooks, 'leader_init_db_if_ready_allowed_units')
    @patch.object(hooks, 'update_cell_db_if_ready_allowed_units')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'quantum_joined')
    @patch.object(hooks, 'nova_api_relation_joined')
    @patch.object(hooks, 'nova_cell_relation_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_noapi_rel(self, configs, cell_joined, api_joined,
                                    quantum_joined, mock_is_db_initialised,
                                    update_db_allowed, init_db_allowed):
        mock_is_db_initialised.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['amqp']
        configs.write = MagicMock()
        self.relation_ids.side_effect = [
            ['nova-cell-api/0'],
            ['nova-api/0'],
            ['quantum-service/0'],
        ]
        self.is_relation_made.return_value = False
        self.network_manager.return_value = 'neutron'
        self.os_release.return_value = 'diablo'
        hooks.amqp_changed()
        self.assertEqual(configs.write.call_args_list,
                         [call('/etc/nova/nova.conf')])
        cell_joined.assert_called_with(rid='nova-cell-api/0')
        api_joined.assert_called_with(rid='nova-api/0')
        quantum_joined.assert_called_with(rid='quantum-service/0',
                                          remote_restart=True)

    @patch.object(hooks, 'canonical_url')
    def test_nova_cell_relation_joined(self, _canonical_url):
        self.uuid.uuid4.return_value = 'bob'
        _canonical_url.return_value = 'http://novaurl'
        hooks.nova_cell_relation_joined(rid='rid',
                                        remote_restart=True)
        self.relation_set.assert_called_with(restart_trigger='bob',
                                             nova_url='http://novaurl:8774/v2',
                                             relation_id='rid')

    @patch.object(hooks, 'CONFIGS')
    def test_nova_cell_relation_changed(self, configs):
        hooks.nova_cell_relation_changed()
        configs.write.assert_called_with('/etc/nova/nova.conf')

    def test_get_cell_type(self):
        self.NovaCellContext().return_value = {
            'cell_type': 'parent',
            'cell_name': 'api',
        }
        self.assertEqual(hooks.get_cell_type(), 'parent')

    @patch.object(hooks, 'canonical_url')
    @patch.object(os, 'rename')
    @patch.object(os.path, 'isfile')
    @patch.object(hooks, 'CONFIGS')
    @patch.object(hooks, 'get_cell_type')
    def test_neutron_api_relation_joined(self, get_cell_type, configs, isfile,
                                         rename, _canonical_url):
        nova_url = 'http://novaurl:8774/v2'
        isfile.return_value = True
        _identity_joined = self.patch('identity_joined')
        self.relation_ids.return_value = ['relid']
        _canonical_url.return_value = 'http://novaurl'
        get_cell_type.return_value = 'parent'
        self.uuid.uuid4.return_value = 'bob'
        hooks.neutron_api_relation_joined(remote_restart=True)
        self.assertTrue(_identity_joined.called)
        self.relation_set.assert_called_with(relation_id=None,
                                             cell_type='parent',
                                             nova_url=nova_url,
                                             restart_trigger='bob')

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
        self.assertTrue(configs.write_all.called)
        self.assertTrue(_compute_joined.called)
        self.assertTrue(_quantum_joined.called)

    @patch.object(hooks, 'canonical_url')
    @patch.object(utils, 'config')
    def test_console_settings_vnc(self, _utils_config, _canonical_url):
        _utils_config.return_value = 'vnc'
        _cc_host = "nova-cc-host1"
        _canonical_url.return_value = 'http://' + _cc_host
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

    @patch.object(hooks, 'canonical_url')
    @patch.object(utils, 'config')
    def test_console_settings_xvpvnc(self, _utils_config, _canonical_url):
        _utils_config.return_value = 'xvpvnc'
        _cc_host = "nova-cc-host1"
        _canonical_url.return_value = 'http://' + _cc_host
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

    @patch.object(hooks, 'canonical_url')
    @patch.object(utils, 'config')
    def test_console_settings_novnc(self, _utils_config, _canonical_url):
        _utils_config.return_value = 'novnc'
        _cc_host = "nova-cc-host1"
        _canonical_url.return_value = 'http://' + _cc_host
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

    @patch.object(hooks, 'canonical_url')
    @patch.object(utils, 'config')
    def test_console_settings_spice(self, _utils_config, _canonical_url):
        _utils_config.return_value = 'spice'
        _cc_host = "nova-cc-host1"
        _canonical_url.return_value = 'http://' + _cc_host
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

    @patch.object(hooks, 'https')
    @patch.object(utils, 'config')
    def test_console_settings_explicit_ip(self, _utils_config, _https):
        _utils_config.return_value = 'spice'
        _https.return_value = False
        _cc_public_host = "public-host"
        self.test_config.set('console-proxy-ip', _cc_public_host)
        _con_sets = hooks.console_settings()
        console_settings = {
            'console_proxy_spice_address': 'http://%s:6082/spice_auto.html' %
                                           (_cc_public_host),
            'console_proxy_spice_host': _cc_public_host,
            'console_proxy_spice_port': 6082,
            'console_access_protocol': 'spice',
            'console_keymap': 'en-us'
        }
        self.assertEqual(_con_sets, console_settings)

    @patch.object(hooks, 'https')
    @patch.object(utils, 'config')
    def test_console_settings_explicit_ip_with_https(self, _utils_config,
                                                     _https):
        _utils_config.return_value = 'spice'
        _https.return_value = True
        _cc_public_host = "public-host"
        self.test_config.set('console-proxy-ip', _cc_public_host)
        _con_sets = hooks.console_settings()
        console_settings = {
            'console_proxy_spice_address': 'https://%s:6082/spice_auto.html' %
                                           (_cc_public_host),
            'console_proxy_spice_host': _cc_public_host,
            'console_proxy_spice_port': 6082,
            'console_access_protocol': 'spice',
            'console_keymap': 'en-us'
        }
        self.assertEqual(_con_sets, console_settings)

    @patch('nova_cc_utils.config')
    def test_ha_relation_joined_no_bound_ip(self, config):
        self.get_hacluster_config.return_value = {
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'vip': '10.10.10.10',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        config.return_value = None
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_nova_haproxy': 'haproxy'},
            'resources': {'res_nova_eth120_vip': 'ocf:heartbeat:IPaddr2',
                          'res_nova_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_nova_eth120_vip': 'params ip="10.10.10.10"'
                ' cidr_netmask="21" nic="eth120"',
                'res_nova_haproxy': 'op monitor interval="5s"'},
            'colocations': {},
            'clones': {'cl_nova_haproxy': 'res_nova_haproxy'}
        }
        self.relation_set.assert_has_calls([
            call(groups={'grp_nova_vips': 'res_nova_eth120_vip'}),
            call(**args),
        ])

    def test_ha_joined_dns_ha(self):
        def _fake_update(resources, resource_params, relation_id=None):
            resources.update({'res_nova_public_hostname': 'ocf:maas:dns'})
            resource_params.update({'res_nova_public_hostname':
                                    'params fqdn="nova.maas" '
                                    'ip_address="10.0.0.1"'})

        self.test_config.set('dns-ha', True)
        self.get_hacluster_config.return_value = {
            'vip': None,
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'os-admin-hostname': None,
            'os-internal-hostname': None,
            'os-public-hostname': 'nova.maas',
        }
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_nova_haproxy': 'haproxy'},
            'resources': {'res_nova_public_hostname': 'ocf:maas:dns',
                          'res_nova_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_nova_public_hostname': 'params fqdn="nova.maas" '
                                            'ip_address="10.0.0.1"',
                'res_nova_haproxy': 'op monitor interval="5s"'},
            'clones': {'cl_nova_haproxy': 'res_nova_haproxy'},
            'colocations': {},
        }
        self.update_dns_ha_resource_params.side_effect = _fake_update

        hooks.ha_joined()
        self.assertTrue(self.update_dns_ha_resource_params.called)
        self.relation_set.assert_called_with(**args)

    @patch('nova_cc_utils.config')
    def test_ha_relation_multi_consoleauth(self, config):
        self.get_hacluster_config.return_value = {
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'vip': '10.10.10.10',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        self.test_config.set('single-nova-consoleauth', False)
        config.return_value = 'novnc'
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_nova_haproxy': 'haproxy'},
            'resources': {'res_nova_eth120_vip': 'ocf:heartbeat:IPaddr2',
                          'res_nova_haproxy': 'lsb:haproxy'},
            'resource_params': {
                'res_nova_eth120_vip': 'params ip="10.10.10.10"'
                ' cidr_netmask="21" nic="eth120"',
                'res_nova_haproxy': 'op monitor interval="5s"'},
            'colocations': {},
            'clones': {'cl_nova_haproxy': 'res_nova_haproxy'}
        }
        self.relation_set.assert_has_calls([
            call(groups={'grp_nova_vips': 'res_nova_eth120_vip'}),
            call(**args),
        ])

    @patch('nova_cc_utils.config')
    def test_ha_relation_single_consoleauth(self, config):
        self.get_hacluster_config.return_value = {
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'vip': '10.10.10.10',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        config.return_value = 'novnc'
        self.get_iface_for_address.return_value = None
        self.get_netmask_for_address.return_value = None
        hooks.ha_joined()
        args = {
            'relation_id': None,
            'corosync_bindiface': 'em0',
            'corosync_mcastport': '8080',
            'init_services': {'res_nova_haproxy': 'haproxy',
                              'res_nova_consoleauth': 'nova-consoleauth'},
            'resources': {'res_nova_eth120_vip': 'ocf:heartbeat:IPaddr2',
                          'res_nova_haproxy': 'lsb:haproxy',
                          'res_nova_consoleauth':
                          'ocf:openstack:nova-consoleauth'},
            'resource_params': {
                'res_nova_eth120_vip': 'params ip="10.10.10.10"'
                ' cidr_netmask="21" nic="eth120"',
                'res_nova_haproxy': 'op monitor interval="5s"',
                'res_nova_consoleauth': 'op monitor interval="5s"'},
            'colocations': {
                'vip_consoleauth': 'inf: res_nova_consoleauth grp_nova_vips'
            },
            'clones': {'cl_nova_haproxy': 'res_nova_haproxy'}
        }
        self.relation_set.assert_has_calls([
            call(groups={'grp_nova_vips': 'res_nova_eth120_vip'}),
            call(**args),
        ])

    @patch.object(hooks, 'update_aws_compat_services')
    @patch.object(hooks, 'is_db_initialised')
    @patch.object(hooks, 'determine_packages')
    @patch.object(hooks, 'service_pause')
    @patch.object(hooks, 'filter_installed_packages')
    @patch('nova_cc_hooks.configure_https')
    @patch('nova_cc_utils.config')
    def test_config_changed_single_consoleauth(self, mock_config,
                                               mock_configure_https,
                                               mock_filter_packages,
                                               mock_service_pause,
                                               mock_determine_packages,
                                               mock_is_db_initialised,
                                               mock_update_aws_compat_svcs):
        mock_determine_packages.return_value = []
        mock_is_db_initialised.return_value = False
        self.config_value_changed.return_value = False
        self.os_release.return_value = 'diablo'

        def cfg(k, v):
            if k == "single-nova-authconsole":
                return True
            return 'novnc'

        config.side_effect = cfg
        rids = {'ha': ['ha:1']}

        def f(r):
            return rids.get(r, [])

        self.relation_ids.side_effect = f
        hooks.config_changed()
        args = {
            'delete_resources': [],
            'init_services': {'res_nova_consoleauth': 'nova-consoleauth'},
            'resources': {'res_nova_consoleauth':
                          'ocf:openstack:nova-consoleauth'},
            'resource_params': {
                'res_nova_consoleauth': 'op monitor interval="5s"'},
            'colocations': {
                'vip_consoleauth': 'inf: res_nova_consoleauth grp_nova_vips'
            }
        }
        self.relation_set.assert_has_calls([
            call(v, **args) for v in rids['ha']
        ])

        mock_service_pause.assert_has_calls([
            call('nova-consoleauth')]
        )
        mock_filter_packages.assert_called_with([])

        self.assertTrue(mock_update_aws_compat_svcs.called)

    @patch.object(hooks, 'is_api_ready')
    def _test_nova_api_relation_joined(self, tgt, is_api_ready):
        is_api_ready.return_value = tgt
        exp = 'yes' if tgt else 'no'
        hooks.nova_api_relation_joined(rid='foo')
        self.relation_set.assert_called_with(
            'foo', **{'nova-api-ready': exp})

    def test_nova_api_relation_joined_ready(self):
        self._test_nova_api_relation_joined(True)

    def test_nova_api_relation_joined_not_ready(self):
        self._test_nova_api_relation_joined(False)

    @patch.object(hooks, 'memcached_common')
    def test_memcache_joined(self, _memcached_common):
        self.get_relation_ip.return_value = 'foo'
        hooks.memcached_joined()
        self.get_relation_ip.assert_called_once_with('memcache')
        self.relation_set.assert_called_once_with(
            relation_id=None,
            relation_settings={'private-address': 'foo'})
        hooks.memcached_joined()
