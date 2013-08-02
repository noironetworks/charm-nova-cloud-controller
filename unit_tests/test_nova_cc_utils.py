from mock import patch, call
from copy import deepcopy
from unit_tests.test_utils import CharmTestCase

import hooks.nova_cc_utils as utils

TO_PATCH = [
    'config',
    'get_os_codename_package',
    'relation_ids',
    '_save_script_rc',
]

SCRIPTRC_ENV_VARS = {
    'OPENSTACK_PORT_MCASTPORT': 5404,
    'OPENSTACK_SERVICE_API_EC2': 'nova-api-ec2',
    'OPENSTACK_SERVICE_API_OS_COMPUTE': 'nova-api-os-compute',
    'OPENSTACK_SERVICE_CERT': 'nova-cert',
    'OPENSTACK_SERVICE_CONDUCTOR': 'nova-conductor',
    'OPENSTACK_SERVICE_OBJECTSTORE': 'nova-objectstore',
    'OPENSTACK_SERVICE_SCHEDULER': 'nova-scheduler',
}


class NovaCCUtilsTests(CharmTestCase):
    def setUp(self):
        super(NovaCCUtilsTests, self).setUp(utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def test_resource_map_quantum(self):
        self.relation_ids.return_value = []
        self.test_config.set('network-manager', 'Quantum')
        _map = utils.resource_map()
        confs = [
            '/etc/quantum/quantum.conf',
            '/etc/quantum/api-paste.ini'
        ]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]

    def test_resource_map_nova_volume(self):
        self.relation_ids.return_value = ['nova-volume-service:0']
        _map = utils.resource_map()
        self.assertIn('nova-api-os-volume',
                      _map['/etc/nova/nova.conf']['services'])

    def test_determine_packages_quantum(self):
        self.relation_ids.return_value = []
        self.test_config.set('network-manager', 'Quantum')
        pkgs = utils.determine_packages()
        self.assertIn('quantum-server', pkgs)

    def test_determine_packages_nova_volume(self):
        self.relation_ids.return_value = ['nova-volume-service:0']
        pkgs = utils.determine_packages()
        self.assertIn('nova-api-os-volume', pkgs)

    def test_determine_packages_base(self):
        self.relation_ids.return_value = []
        pkgs = utils.determine_packages()
        ex = list(set(utils.BASE_PACKAGES + utils.BASE_SERVICES))
        self.assertEquals(ex, pkgs)

    @patch.object(utils, 'restart_map')
    def test_determine_ports(self, restart_map):
        restart_map.return_value = {
            '/etc/nova/nova.conf': ['nova-api-os-compute', 'nova-api-ec2'],
            '/etc/quantum/quantum.conf': ['quantum-server'],
        }
        ports = utils.determine_ports()
        ex = [8773, 8774, 9696]
        self.assertEquals(ex, sorted(ports))

    def test_save_script_rc_base(self):
        self.relation_ids.return_value = []
        utils.save_script_rc()
        self._save_script_rc.called_with(**SCRIPTRC_ENV_VARS)

    def test_save_script_quantum(self):
        self.relation_ids.return_value = []
        self.test_config.set('network-manager', 'Quantum')
        utils.save_script_rc()
        _ex = deepcopy(SCRIPTRC_ENV_VARS)
        _ex['OPENSTACK_SERVICE_API_QUANTUM'] = 'quantum-server'
        self._save_script_rc.called_with(**_ex)

    def test_save_script_nova_volume(self):
        self.relation_ids.return_value = ['nvol:0']
        utils.save_script_rc()
        _ex = deepcopy(SCRIPTRC_ENV_VARS)
        _ex['OPENSTACK_SERVICE_API_OS_VOL'] = 'nova-api-os-volume'
        self._save_script_rc.called_with(**_ex)

    def test_determine_volume_service_essex(self):
        self.get_os_codename_package.return_value = 'essex'
        self.assertEquals('nova-volume', utils.volume_service())

    def test_determine_volume_service_folsom_cinder(self):
        self.get_os_codename_package.return_value = 'folsom'
        self.relation_ids.return_value = ['cinder:0']
        self.assertEquals('cinder', utils.volume_service())

    def test_determine_volume_service_folsom_nova_vol(self):
        self.get_os_codename_package.return_value = 'folsom'
        self.relation_ids.return_value = []
        self.assertEquals('nova-volume', utils.volume_service())

    def test_determine_volume_service_grizzly_and_beyond(self):
        pass
