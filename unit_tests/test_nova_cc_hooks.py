from mock import MagicMock, patch

from unit_tests.test_utils import CharmTestCase

import hooks.nova_cc_utils as utils

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

import hooks.nova_cc_hooks as hooks

utils.register_configs = _reg
utils.restart_map = _map


TO_PATCH = [
    'apt_update',
    'apt_install',
    'configure_installation_source',
    'do_openstack_upgrade',
    'openstack_upgrade_available',
    'config',
    'determine_packages',
    'determine_ports',
    'open_port',
    'save_script_rc',
]


class NovaCCHooksTests(CharmTestCase):
    def setUp(self):
        super(NovaCCHooksTests, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get

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
