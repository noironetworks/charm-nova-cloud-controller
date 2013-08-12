from mock import patch, MagicMock
from unit_tests.test_utils import CharmTestCase


from charmhelpers.core import hookenv
_conf = hookenv.config
hookenv.config = MagicMock()

import hooks.misc_utils as utils

hookenv.config = _conf

TO_PATCH = [
    'apt_install',
    'filter_installed_packages',
    'config',
    'log',
    'get_os_codename_package',
    'get_os_codename_install_source',
    'relation_get',
    'unit_private_ip'
]


class NovaCCMiscUtilsTests(CharmTestCase):
    def setUp(self):
        super(NovaCCMiscUtilsTests, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get

    def _set_os_codename(self, codename):
        self.get_os_codename_package.return_value = codename

    def test_network_manager_non_sdn(self):
        self.test_config.set('network-manager', 'FlatDHCPManager')
        self._set_os_codename('essex')
        self.assertEquals('flatdhcpmanager', utils.network_manager())

    def test_network_manager_q_n_unsupported(self):
        self.test_config.set('network-manager', 'quantum')
        self._set_os_codename('essex')
        self.assertRaises(Exception, utils.network_manager)

    def test_network_manager_quantum_folsom(self):
        self.test_config.set('network-manager', 'quantum')
        self._set_os_codename('folsom')
        self.assertEquals('quantum', utils.network_manager())

    def test_network_manager_quantum_grizzly(self):
        self.test_config.set('network-manager', 'neutron')
        self._set_os_codename('grizzly')
        self.assertEquals('quantum', utils.network_manager())

    def test_network_manager_neutron_havana(self):
        self.test_config.set('network-manager', 'neutron')
        self._set_os_codename('havana')
        self.assertEquals('neutron', utils.network_manager())

    def test_network_manager_quantum_havana(self):
        self.test_config.set('network-manager', 'quantum')
        self._set_os_codename('havana')
        self.assertEquals('neutron', utils.network_manager())

    @patch.object(utils, 'network_manager')
    def test_network_plugin_attribute_quantum(self, nm):
        nm.return_value = 'quantum'
        self.assertEquals(
            utils.network_plugin_attribute('ovs', 'config'),
            '/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini')

    @patch.object(utils, 'network_manager')
    def test_network_plugin_attribute_neutron(self, nm):
        nm.return_value = 'neutron'
        self.assertEquals(
            utils.network_plugin_attribute('ovs', 'config'),
            '/etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini')


class NovaNeutronContextTests(CharmTestCase):
    def setUp(self):
        super(NovaNeutronContextTests, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get
        self.unit_private_ip.return_value = '10.0.0.1'

    def test_neutron_nova_context_nova_network(self):
        ctxts = [utils.NeutronContext(), utils.NeutronCCContext(),
                 utils.NeutronComputeContext()]
        for ctxt in ctxts:
            self.assertEquals({}, ctxt())

    @patch.object(utils, '_save_flag_file')
    def test_neutron_cc_context_neutron_quantum(self, ff):
        self.test_config.set('network-manager', 'Quantum')

        ex_keys = ['core_plugin', 'local_ip',
                   'network_manager', 'neutron_plugin']

        self.get_os_codename_package.return_value = 'grizzly'
        ctxt = utils.NeutronCCContext()
        self.assertEquals(sorted(ex_keys), sorted(ctxt().iterkeys()))
        self.assertTrue(ctxt()['core_plugin'].startswith('quantum'))

        self.test_config.set('network-manager', 'Neutron')
        self.get_os_codename_package.return_value = 'havana'
        ctxt = utils.NeutronCCContext()
        self.assertEquals(sorted(ex_keys), sorted(ctxt().iterkeys()))
        self.assertTrue(ctxt()['core_plugin'].startswith(''))

    @patch.object(utils, '_save_flag_file')
    def test_neutron_compute_context_quantum(self, ff):
        self.test_relation.set({
            'network_manager': 'quantum',
            'quantum_plugin': 'ovs',
            'quantum_security_groups': 'yes',
        })

        ex_keys = ['network_manager', 'neutron_security_groups',
                   'neutron_firewall_driver', 'local_ip', 'core_plugin',
                   'neutron_plugin', 'libvirt_vif_driver']

        self.test_config.set('network-manager', 'Quantum')
        self.get_os_codename_package.return_value = 'folsom'
        ctxt = utils.NeutronComputeContext()
        result = ctxt()
        self.assertTrue(ctxt()['core_plugin'].startswith('quantum'))
        self.assertEquals(sorted(ex_keys), sorted(result))

        self.test_config.set('network-manager', 'Neutron')
        self.get_os_codename_package.return_value = 'havana'
        ctxt = utils.NeutronComputeContext()
        result = ctxt()
        self.assertTrue(ctxt()['core_plugin'].startswith('neutron'))
        self.assertEquals(sorted(ex_keys), sorted(result))
