from mock import MagicMock, patch

from test_utils import CharmTestCase

import nova_cc_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

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
    'determine_packages',
    'determine_ports',
    'open_port',
    'relation_get',
    'relation_set',
    'ssh_compute_add',
    'ssh_known_hosts_b64',
    'ssh_authorized_keys_b64',
    'save_script_rc',
]


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
