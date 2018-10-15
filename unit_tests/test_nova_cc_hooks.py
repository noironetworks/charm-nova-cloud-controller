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

from mock import MagicMock, patch, call
import os
import tempfile

from unit_tests.test_utils import CharmTestCase

import charmhelpers.contrib.hardening.harden as harden

import hooks.nova_cc_utils as utils
import hooks.nova_cc_hooks as hooks


TO_PATCH = [
    'charmhelpers.contrib.hahelpers.cluster.get_hacluster_config',
    'charmhelpers.contrib.hahelpers.cluster.is_clustered',
    'charmhelpers.contrib.network.ip.get_iface_for_address',
    'charmhelpers.contrib.network.ip.get_netmask_for_address',
    'charmhelpers.contrib.network.ip.get_relation_ip',
    'charmhelpers.contrib.openstack.ha.utils.update_dns_ha_resource_params',
    'charmhelpers.contrib.openstack.neutron.network_manager',
    'charmhelpers.contrib.openstack.utils.configure_installation_source',
    'charmhelpers.contrib.openstack.utils.config_value_changed',
    'charmhelpers.contrib.openstack.utils.is_unit_paused_set',
    'charmhelpers.contrib.openstack.utils.openstack_upgrade_available',
    'charmhelpers.contrib.openstack.utils.os_release',
    'charmhelpers.core.hookenv.charm_dir',
    'charmhelpers.core.hookenv.config',
    'charmhelpers.core.hookenv.is_leader',
    'charmhelpers.core.hookenv.is_relation_made',
    'charmhelpers.core.hookenv.local_unit',
    'charmhelpers.core.hookenv.log',
    'charmhelpers.core.hookenv.open_port',
    'charmhelpers.core.hookenv.related_units',
    'charmhelpers.core.hookenv.relation_get',
    'charmhelpers.core.hookenv.relation_ids',
    'charmhelpers.core.hookenv.relation_set',
    'charmhelpers.core.hookenv.status_set',
    'charmhelpers.core.hookenv.unit_get',
    'charmhelpers.core.host.service_pause',
    'charmhelpers.core.host.service_reload',
    'charmhelpers.core.host.service_resume',
    'charmhelpers.fetch.apt_install',
    'charmhelpers.fetch.apt_update',
    'charmhelpers.payload.execd.execd_preinstall',
    'hooks.nova_cc_utils.determine_endpoints',
    'hooks.nova_cc_utils.determine_packages',
    'hooks.nova_cc_utils.determine_ports',
    'hooks.nova_cc_utils.do_openstack_upgrade',
    'hooks.nova_cc_utils.keystone_ca_cert_b64',
    'hooks.nova_cc_utils.migrate_nova_databases',
    'hooks.nova_cc_utils.placement_api_enabled',
    'hooks.nova_cc_utils.save_script_rc',
    'hooks.nova_cc_utils.serial_console_settings',
    'hooks.nova_cc_utils.services',
    'hooks.nova_cc_utils.ssh_authorized_keys_lines',
    'hooks.nova_cc_utils.ssh_compute_add',
    'hooks.nova_cc_utils.ssh_known_hosts_lines',
    'uuid',
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

        hooks.CONFIGS = None  # reset for each test
        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get
        self.charm_dir.return_value = '/var/lib/juju/charms/nova/charm'
        self.is_unit_paused_set.return_value = False
        # disable hardening for unit tests
        harden._DISABLE_HARDENING_FOR_UNIT_TEST = True

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

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch.object(hooks, 'update_nrpe_config')
    @patch.object(utils, 'resource_map')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade(self, conf_https, mock_filter_packages,
                                       mock_is_db_initialised,
                                       mock_update_nova_consoleauth_config,
                                       mock_update_aws_compat_services,
                                       mock_resource_map,
                                       mock_update_nrpe_config,
                                       mock_get_shared_metadatasecret,
                                       mock_set_shared_metadatasecret):
        mock_resource_map.return_value = {}
        self.get_shared_metadatasecret = None
        self.determine_packages.return_value = []
        self.is_leader.return_value = True
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.resolve_CONFIGS()
        hooks.config_changed()
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_config.called)
        self.assertTrue(mock_update_aws_compat_services.called)

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(hooks, 'update_nrpe_config')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_ocata(self,
                                  conf_https,
                                  mock_filter_packages,
                                  mock_is_db_initialised,
                                  mock_update_nova_consoleauth_config,
                                  mock_update_aws_compat_services,
                                  mock_update_nrpe_config,
                                  mock_sub_ctxt,
                                  mock_get_shared_metadatasecret,
                                  mock_set_shared_metadatasecret):
        mock_get_shared_metadatasecret.return_value = None
        self.is_leader.return_value = True
        self.determine_packages.return_value = []
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.resolve_CONFIGS()
        # probably need the with patch.object from below
        with patch.object(hooks.CONFIGS, 'write_all') as wa:
            hooks.config_changed()
            self.assertTrue(wa.called)
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_config.called)
        self.assertTrue(mock_update_aws_compat_services.called)
        mock_set_shared_metadatasecret.assert_called_once_with()

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch.object(hooks, 'update_nrpe_config')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_juno(self, conf_https,
                                            mock_filter_packages,
                                            mock_is_db_initialised,
                                            mock_update_nova_consoleauth_cfg,
                                            mock_update_aws_compat_services,
                                            mock_update_nrpe_config,
                                            mock_sub_ctxt,
                                            mock_get_shared_metadatasecret,
                                            mock_set_shared_metadatasecret):
        self.determine_packages.return_value = []
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'juno'
        hooks.resolve_CONFIGS()
        with patch.object(hooks.CONFIGS, 'write_all') as wa:
            hooks.config_changed()
            self.assertTrue(wa.called)
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_cfg.called)
        self.assertTrue(mock_update_aws_compat_services.called)
        self.service_pause.assert_called_with('neutron-server')

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch.object(hooks, 'update_nrpe_config')
    @patch.object(utils, 'resource_map')
    @patch('charmhelpers.contrib.openstack.context.SubordinateConfigContext')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_no_upgrade_juno_no_neutron_server(
            self,
            conf_https,
            mock_filter_packages,
            mock_is_db_initialised,
            mock_update_nova_consoleauth_cfg,
            mock_update_aws_compat_services,
            mock_sub_ctxt,
            mock_resource_map,
            mock_update_nrpe_config,
            mock_get_shared_metadatasecret,
            mock_set_shared_metadatasecret):
        mock_resource_map.return_value = {}
        self.determine_packages.return_value = []
        self.test_config.set('console-access-protocol', 'dummy')
        self.openstack_upgrade_available.return_value = False
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'juno'
        self.service_pause.side_effect = ValueError
        hooks.resolve_CONFIGS()
        with patch.object(hooks.CONFIGS, 'write_all'):
            hooks.config_changed()
        self.assertTrue(self.save_script_rc.called)
        mock_filter_packages.assert_called_with([])
        self.assertTrue(mock_update_nova_consoleauth_cfg.called)
        self.assertTrue(mock_update_aws_compat_services.called)
        self.service_pause.assert_called_with('neutron-server')

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch.object(hooks, 'update_nrpe_config')
    @patch.object(utils, 'resource_map')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'quantum_joined')
    @patch('charmhelpers.contrib.openstack.ip.unit_get')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch.object(hooks, 'db_joined')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch('charmhelpers.contrib.openstack.ip.service_name',
           lambda *args: 'nova-cloud-controller')
    @patch.object(hooks, 'cluster_joined')
    @patch.object(hooks, 'identity_joined')
    @patch.object(hooks, 'neutron_api_relation_joined')
    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'compute_joined')
    @patch.object(hooks, 'nova_cell_api_relation_joined')
    def test_config_changed_with_upgrade(self,
                                         mock_nova_cell_api_relation_joined,
                                         mock_compute_joined,
                                         conf_https, neutron_api_joined,
                                         identity_joined, cluster_joined,
                                         mock_filter_packages, db_joined,
                                         mock_relids,
                                         mock_unit_get,
                                         mock_quantum_joined,
                                         mock_is_db_initialised,
                                         mock_update_nova_consoleauth_config,
                                         mock_update_aws_compat_services,
                                         mock_resource_map,
                                         mock_update_nrpe_config,
                                         mock_get_shared_metadatasecret,
                                         mock_set_shared_metadatasecret):
        mock_resource_map.return_value = {}
        self.determine_packages.return_value = []
        mock_is_db_initialised.return_value = False
        self.openstack_upgrade_available.return_value = True
        self.relation_ids.return_value = ['generic_rid']
        self.test_config.set('console-access-protocol', 'dummy')
        mock_relids.return_value = []
        mock_unit_get.return_value = '127.0.0.1'
        self.os_release.return_value = 'diablo'
        hooks.resolve_CONFIGS()
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

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch.object(hooks, 'update_nrpe_config')
    @patch.object(utils, 'resource_map')
    @patch('charmhelpers.contrib.hahelpers.cluster.relation_ids')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch.object(hooks, 'update_nova_consoleauth_config')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    @patch.object(hooks, 'compute_joined')
    @patch.object(hooks, 'compute_changed')
    def test_config_changed_region_change(self, mock_compute_changed,
                                          mock_compute_joined,
                                          mock_config_https,
                                          mock_filter_packages,
                                          mock_is_db_initialised,
                                          mock_update_nova_consoleauth_config,
                                          mock_update_aws_compat_services,
                                          mock_relation_ids,
                                          mock_resource_map,
                                          mock_update_nrpe_config,
                                          mock_get_shared_metadatasecret,
                                          mock_set_shared_metadatasecret):
        mock_resource_map.return_value = {}
        self.openstack_upgrade_available.return_value = False
        self.config_value_changed.return_value = True
        self.related_units.return_value = ['unit/0']
        self.relation_ids.side_effect = \
            lambda x: ['generic_rid'] if x == 'cloud-compute' else []
        mock_is_db_initialised.return_value = False
        self.os_release.return_value = 'diablo'
        hooks.resolve_CONFIGS()
        hooks.config_changed()
        mock_compute_changed.assert_has_calls([call('generic_rid', 'unit/0')])
        mock_compute_joined.assert_has_calls(
            [call(rid='generic_rid', remote_restart=False)])
        self.assertTrue(mock_update_nova_consoleauth_config.called)
        self.assertTrue(mock_update_aws_compat_services.called)

    @patch('hooks.nova_cc_utils.is_cellv2_init_ready')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'nova_api_relation_joined')
    def test_compute_changed_nova_api_trigger(self, api_joined,
                                              mock_is_db_initialised,
                                              mock_is_cellv2_init_ready):
        self.relation_ids.return_value = ['nova-api/0']
        mock_is_db_initialised.return_value = False
        mock_is_cellv2_init_ready.return_value = False
        hooks.compute_changed()
        api_joined.assert_called_with(rid='nova-api/0')

    @patch('hooks.nova_cc_utils.is_cellv2_init_ready')
    @patch('hooks.nova_cc_utils.is_db_initialised')
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
        self.relation_set.assert_has_calls(expected_relations, any_order=True)

    @patch('hooks.nova_cc_utils.is_cellv2_init_ready')
    @patch('hooks.nova_cc_utils.is_db_initialised')
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
        self.relation_set.assert_has_calls(expected_relations, any_order=True)

    @patch('hooks.nova_cc_utils.is_cellv2_init_ready')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('hooks.nova_cc_utils.add_hosts_to_cell')
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

    @patch('hooks.nova_cc_utils.is_cellv2_init_ready')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('hooks.nova_cc_utils.add_hosts_to_cell')
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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    @patch.object(hooks, '_auth_config')
    def test_compute_joined_neutron(self, auth_config, _canonical_url):
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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    @patch('hooks.nova_cc_context.NeutronAPIContext')
    @patch.object(hooks, '_auth_config')
    def test_compute_joined_neutron_api_rel(self, auth_config, napi,
                                            _canonical_url):
        def mock_NeutronAPIContext():
            return {
                'neutron_plugin': 'bob',
                'neutron_security_groups': 'yes',
                'neutron_url': 'http://nova-cc-host1:9696',
            }

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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    @patch('charmhelpers.contrib.openstack.ip.is_clustered')
    def test_identity_joined(self, _is_clustered, mock_canonical_url):
        _is_clustered.return_value = False
        mock_canonical_url.side_effect = [
            'http://ncc.example.com',
            'http://127.0.0.1',
            'http://127.0.0.2',
        ]
        self.test_config.set('os-public-hostname', 'ncc.example.com')
        hooks.identity_joined()
        mock_canonical_url.assert_has_calls([
            call(hooks.CONFIGS, hooks.ch_ip.PUBLIC),
            call(hooks.CONFIGS, hooks.ch_ip.INTERNAL),
            call(hooks.CONFIGS, hooks.ch_ip.ADMIN)])
        self.determine_endpoints.assert_called_with(
            'http://ncc.example.com',
            'http://127.0.0.1',
            'http://127.0.0.2'
        )

    def test_identity_joined_partial_cluster(self):
        self.is_clustered.return_value = False
        self.test_config.set('vip', '10.0.0.10')
        hooks.identity_joined()
        self.assertFalse(self.relation_set.called)

    @patch.object(utils, 'resource_map')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_missing_relation_data(
            self, configs, mock_resource_map):
        mock_resource_map.return_value = {}
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

    @patch.object(utils, 'resource_map')
    @patch.object(hooks, 'nova_api_relation_joined')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed(self, configs,
                        mock_is_db_initialised, api_joined, mock_resource_map):
        self.relation_ids.return_value = ['nova-api/0']
        mock_is_db_initialised.return_value = False
        mock_resource_map.return_value = {}
        'No database migration is attempted when ACL list is not present'
        self.os_release.return_value = 'diablo'
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.assertFalse(self.migrate_nova_databases.called)
        api_joined.asert_called_with(rid='nova-api/0')

    @patch.object(utils, 'resource_map')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_allowed(self, configs, mock_is_db_initialised,
                                mock_resource_map):
        mock_is_db_initialised.return_value = False
        mock_resource_map.return_value = {}
        allowed_units = 'nova-cloud-controller/0 nova-cloud-controller/3'
        self.test_relation.set({
            'nova_allowed_units': allowed_units,
        })
        self.local_unit.return_value = 'nova-cloud-controller/3'
        self.os_release.return_value = 'diablo'
        self.is_leader.return_value = True
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.migrate_nova_databases.assert_called_with()

    @patch.object(utils, 'resource_map')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_not_allowed(self, configs, mock_is_db_initialised,
                                    mock_resource_map):
        mock_is_db_initialised.return_value = False
        mock_resource_map.return_value = {}
        allowed_units = 'nova-cloud-controller/0 nova-cloud-controller/3'
        self.test_relation.set({
            'nova_allowed_units': allowed_units,
        })
        self.local_unit.return_value = 'nova-cloud-controller/1'
        self.os_release.return_value = 'diablo'
        self._shared_db_test(configs)
        self.assertTrue(configs.write_all.called)
        self.assertFalse(self.migrate_nova_databases.called)

    @patch.object(utils, 'resource_map')
    @patch.object(hooks, 'quantum_joined')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'compute_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_db_changed_remote_restarts(self, configs, comp_joined,
                                        mock_is_db_initialised,
                                        quantum_joined,
                                        mock_resource_map):
        mock_is_db_initialised.return_value = False
        mock_resource_map.return_value = {}

        def _relation_ids(rel):
            relid = {
                'cloud-compute': ['nova-compute/0'],
                'nova-cell-api': ['nova-cell-controller/0'],
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
        self.is_leader.return_value = True
        self._shared_db_test(configs)
        comp_joined.assert_called_with(remote_restart=True,
                                       rid='nova-compute/0')
        quantum_joined.assert_called_with(remote_restart=True,
                                          rid='neutron-gateway/0')
        self.migrate_nova_databases.assert_called_with()

    @patch.object(hooks, 'CONFIGS')
    def test_amqp_relation_broken(self, configs):
        configs.write = MagicMock()
        self.relation_ids.return_value = ['nova-cell-api/0']
        hooks.relation_broken()
        self.assertTrue(configs.write_all.called)

    @patch.object(hooks, 'update_child_cell_records')
    @patch.object(utils, 'resource_map')
    @patch.object(hooks, 'leader_init_db_if_ready_allowed_units')
    @patch.object(hooks, 'update_cell_db_if_ready_allowed_units')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'quantum_joined')
    @patch.object(hooks, 'nova_api_relation_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_api_rel(self, configs, api_joined,
                                  quantum_joined, mock_is_db_initialised,
                                  update_db_allowed, init_db_allowed,
                                  mock_resource_map,
                                  mock_update_child_cell_records):
        mock_resource_map.return_value = {}
        self.relation_ids.side_effect = [
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
        api_joined.assert_called_with(rid='nova-api/0')
        quantum_joined.assert_called_with(rid='quantum-service/0',
                                          remote_restart=True)

    @patch.object(hooks, 'update_child_cell_records')
    @patch.object(hooks, 'leader_init_db_if_ready_allowed_units')
    @patch.object(hooks, 'update_cell_db_if_ready_allowed_units')
    @patch.object(utils, 'resource_map')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch.object(hooks, 'quantum_joined')
    @patch.object(hooks, 'nova_api_relation_joined')
    @patch.object(hooks, 'CONFIGS')
    def test_amqp_changed_noapi_rel(self,
                                    configs,
                                    api_joined,
                                    quantum_joined,
                                    mock_is_db_initialised,
                                    mock_resource_map,
                                    update_db_allowed,
                                    init_db_allowed,
                                    mock_update_child_cell_records):
        mock_resource_map.return_value = {}
        mock_is_db_initialised.return_value = False
        configs.complete_contexts = MagicMock()
        configs.complete_contexts.return_value = ['amqp']
        configs.write = MagicMock()
        self.relation_ids.side_effect = [
            ['nova-api/0'],
            ['quantum-service/0'],
        ]
        self.is_relation_made.return_value = False
        self.network_manager.return_value = 'neutron'
        self.os_release.return_value = 'diablo'
        hooks.amqp_changed()
        self.assertEqual(configs.write.call_args_list,
                         [call('/etc/nova/nova.conf')])
        api_joined.assert_called_with(rid='nova-api/0')
        quantum_joined.assert_called_with(rid='quantum-service/0',
                                          remote_restart=True)

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    @patch.object(os, 'rename')
    @patch.object(os.path, 'isfile')
    @patch.object(hooks, 'CONFIGS')
    def test_neutron_api_relation_joined(self, configs, isfile,
                                         rename, _canonical_url):
        nova_url = 'http://novaurl:8774/v2'
        isfile.return_value = True
        _identity_joined = self.patch('identity_joined')
        self.relation_ids.return_value = ['relid']
        _canonical_url.return_value = 'http://novaurl'
        self.uuid.uuid4.return_value = 'bob'
        hooks.neutron_api_relation_joined(remote_restart=True)
        self.assertTrue(_identity_joined.called)
        self.relation_set.assert_called_with(relation_id=None,
                                             nova_url=nova_url,
                                             restart_trigger='bob')

    @patch('hooks.nova_cc_utils.resource_map')
    @patch.object(hooks, 'CONFIGS')
    def test_neutron_api_relation_changed(self, configs, mock_resource_map):
        mock_resource_map.return_value = {}
        self.relation_ids.return_value = ['relid']
        _compute_joined = self.patch('compute_joined')
        _quantum_joined = self.patch('quantum_joined')
        hooks.neutron_api_relation_changed()
        self.assertTrue(configs.write.called_with('/etc/nova/nova.conf'))
        self.assertTrue(_compute_joined.called)
        self.assertTrue(_quantum_joined.called)

    @patch.object(utils, 'resource_map')
    @patch.object(os, 'remove')
    @patch.object(os.path, 'isfile')
    @patch.object(hooks, 'CONFIGS')
    def test_neutron_api_relation_broken(self, configs, isfile, remove,
                                         mock_resource_map):
        mock_resource_map.return_value = {}
        isfile.return_value = True
        self.relation_ids.return_value = ['relid']
        _compute_joined = self.patch('compute_joined')
        _quantum_joined = self.patch('quantum_joined')
        hooks.neutron_api_relation_broken()
        self.assertTrue(configs.write_all.called)
        self.assertTrue(_compute_joined.called)
        self.assertTrue(_quantum_joined.called)

    @patch.object(utils, 'resource_map')
    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    def test_console_settings_vnc(self, _canonical_url, mock_resource_map):
        self.test_config.set('console-access-protocol', 'vnc')
        self.os_release.return_value = 'kilo'
        mock_resource_map.return_value = {}
        _cc_host = "nova-cc-host1"
        _canonical_url.return_value = 'http://' + _cc_host
        hooks.resolve_CONFIGS()
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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    def test_console_settings_xvpvnc(self, _canonical_url):
        self.test_config.set('console-access-protocol', 'xvpvnc')
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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    def test_console_settings_novnc(self, _canonical_url):
        self.test_config.set('console-access-protocol', 'novnc')
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

    @patch('charmhelpers.contrib.openstack.ip.canonical_url')
    def test_console_settings_spice(self, _canonical_url):
        self.test_config.set('console-access-protocol', 'spice')
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

    @patch('charmhelpers.contrib.hahelpers.cluster.https')
    def test_console_settings_explicit_ip(self, _https):
        self.test_config.set('console-access-protocol', 'spice')
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

    @patch('charmhelpers.contrib.hahelpers.cluster.https')
    def test_console_settings_explicit_ip_with_https(self, _https):
        self.test_config.set('console-access-protocol', 'spice')
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

    def test_ha_relation_joined_no_bound_ip(self):
        self.get_hacluster_config.return_value = {
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'vip': '10.10.10.10',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
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

    def test_ha_relation_multi_consoleauth(self):
        self.get_hacluster_config.return_value = {
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'vip': '10.10.10.10',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        self.test_config.set('single-nova-consoleauth', False)
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

    def test_ha_relation_single_consoleauth(self):
        self.get_hacluster_config.return_value = {
            'ha-bindiface': 'em0',
            'ha-mcastport': '8080',
            'vip': '10.10.10.10',
        }
        self.test_config.set('vip_iface', 'eth120')
        self.test_config.set('vip_cidr', '21')
        self.test_config.set('console-access-protocol', 'novnc')
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

    @patch.object(utils, 'set_shared_metadatasecret')
    @patch.object(utils, 'get_shared_metadatasecret')
    @patch.object(hooks, 'update_nrpe_config')
    @patch.object(utils, 'resource_map')
    @patch('hooks.nova_cc_utils.update_aws_compat_services')
    @patch('hooks.nova_cc_utils.is_db_initialised')
    @patch('charmhelpers.fetch.filter_installed_packages')
    @patch.object(hooks, 'configure_https')
    def test_config_changed_single_consoleauth(self,
                                               mock_configure_https,
                                               mock_filter_packages,
                                               mock_is_db_initialised,
                                               mock_update_aws_compat_svcs,
                                               mock_resource_map,
                                               mock_update_nrpe_config,
                                               mock_get_shared_metadatasecret,
                                               mock_set_shared_metadatasecret):
        mock_resource_map.return_value = {}
        self.determine_packages.return_value = []
        mock_is_db_initialised.return_value = False
        self.config_value_changed.return_value = False
        self.os_release.return_value = 'diablo'

        self.test_config.set('single-nova-consoleauth', True)
        self.test_config.set('console-access-protocol', 'novnc')

        rids = {'ha': ['ha:1']}
        self.relation_ids.side_effect = lambda r: rids.get(r, [])

        hooks.resolve_CONFIGS()
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

        self.service_pause.assert_has_calls([
            call('nova-consoleauth')]
        )
        mock_filter_packages.assert_called_with([])

        self.assertTrue(mock_update_aws_compat_svcs.called)

    @patch('hooks.nova_cc_utils.is_api_ready')
    def helper_test_nova_api_relation_joined(self, tgt, is_api_ready):
        is_api_ready.return_value = tgt
        exp = 'yes' if tgt else 'no'
        hooks.nova_api_relation_joined(rid='foo')
        self.relation_set.assert_called_with(
            'foo', **{'nova-api-ready': exp})

    def test_nova_api_relation_joined_ready(self):
        self.helper_test_nova_api_relation_joined(True)

    def test_nova_api_relation_joined_not_ready(self):
        self.helper_test_nova_api_relation_joined(False)

    @patch.object(hooks, 'memcached_common')
    def test_memcache_joined(self, _memcached_common):
        self.get_relation_ip.return_value = 'foo'
        hooks.memcached_joined()
        self.get_relation_ip.assert_called_once_with('memcache')
        self.relation_set.assert_called_once_with(
            relation_id=None,
            relation_settings={'private-address': 'foo'})
        hooks.memcached_joined()
