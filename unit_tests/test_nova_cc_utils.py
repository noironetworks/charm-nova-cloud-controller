from mock import patch, MagicMock
from copy import deepcopy
from unit_tests.test_utils import CharmTestCase, patch_open

import hooks.nova_cc_utils as utils

TO_PATCH = [
    'config',
    'log',
    'get_os_codename_package',
    'relation_ids',
    'remote_unit',
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


AUTHORIZED_KEYS = """
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC27Us7lSjCpa7bumXAgc nova-compute-1
ssh-rsa BBBBB3NzaC1yc2EBBBBDBQBBBBBBBQC27Us7lSjCpa7bumXBgc nova-compute-2
ssh-rsa CCCCB3NzaC1yc2ECCCCDCQCBCCCBCQC27Us7lSjCpa7bumXCgc nova-compute-3
"""


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

    @patch.object(utils, 'remove_known_host')
    @patch.object(utils, 'ssh_known_host_key')
    @patch('subprocess.check_output')
    def test_add_known_host_exists(self, check_output, host_key, rm):
        check_output.return_value = 'fookey'
        host_key.return_value = 'fookey'
        with patch_open() as (_open, _file):
            utils.add_known_host('foohost')
            self.assertFalse(rm.called)
            self.assertFalse(_file.write.called)

    @patch.object(utils, 'known_hosts')
    @patch.object(utils, 'remove_known_host')
    @patch.object(utils, 'ssh_known_host_key')
    @patch('subprocess.check_output')
    def test_add_known_host_exists_outdated(
            self, check_output, host_key, rm, known_hosts):
        check_output.return_value = 'fookey'
        host_key.return_value = 'fookey_old'
        with patch_open() as (_open, _file):
            utils.add_known_host('foohost')
            rm.assert_called_with('foohost')

    @patch.object(utils, 'known_hosts')
    @patch.object(utils, 'remove_known_host')
    @patch.object(utils, 'ssh_known_host_key')
    @patch('subprocess.check_output')
    def test_add_known_host_exists_added(
            self, check_output, host_key, rm, known_hosts):
        check_output.return_value = 'fookey'
        host_key.return_value = None
        with patch_open() as (_open, _file):
            _file.write = MagicMock()
            utils.add_known_host('foohost')
            self.assertFalse(rm.called)
            _file.write.assert_called_with('fookey\n')

    @patch('os.mkdir')
    @patch('os.path.isdir')
    def test_ssh_directory_for_unit(self, isdir, mkdir):
        self.remote_unit.return_value = 'nova-compute/0'
        isdir.return_value = False
        self.assertEquals(utils.ssh_directory_for_unit(),
                          '/etc/nova/compute_ssh/nova-compute')

    @patch.object(utils, 'ssh_directory_for_unit')
    def test_known_hosts(self, ssh_dir):
        ssh_dir.return_value = '/tmp/foo'
        self.assertEquals(utils.known_hosts(), '/tmp/foo/known_hosts')

    @patch.object(utils, 'ssh_directory_for_unit')
    def test_authorized_keys(self, ssh_dir):
        ssh_dir.return_value = '/tmp/foo'
        self.assertEquals(utils.authorized_keys(), '/tmp/foo/authorized_keys')

    @patch.object(utils, 'known_hosts')
    @patch('subprocess.check_call')
    def test_remove_host_key(self, check_call, known_hosts):
        known_hosts.return_value = '/tmp/known_hosts'
        utils.remove_known_host('foo')
        check_call.assert_called_with([
            'ssh-kegen', '-f', known_hosts(), '-R', 'foo'])

    @patch.object(utils, 'authorized_keys')
    def test_ssh_authorized_key_exists(self, keys):
        key = 'BBBBB3NzaC1yc2EBBBBDBQBBBBBBBQC27Us7lSjCpa7bumXBgc'
        with patch_open() as (_open, _file):
            _file.read.return_value = AUTHORIZED_KEYS
            self.assertTrue(utils.ssh_authorized_key_exists(key))

    @patch.object(utils, 'authorized_keys')
    def test_ssh_authorized_key_doesnt_exist(self, keys):
        key = ('xxxx')
        with patch_open() as (_open, _file):
            _file.read = MagicMock()
            _file.readreturn_value = AUTHORIZED_KEYS
            self.assertFalse(utils.ssh_authorized_key_exists(key))

    @patch.object(utils, 'known_hosts')
    @patch.object(utils, 'authorized_keys')
    @patch('os.path.isfile')
    def test_ssh_compute_remove(self, isfile, auth_key, known_host):
        isfile.return_value = False
        utils.ssh_compute_remove()
        self.assertFalse(self.remote_unit.called)

        keys_removed = (
            "\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC27Us7lSjCpa7bumXAgc "
            "nova-compute-1\n"
            "ssh-rsa CCCCB3NzaC1yc2ECCCCDCQCBCCCBCQC27Us7lSjCpa7bumXCgc "
            "nova-compute-3\n"
        )
        isfile.return_value = True
        self.remote_unit.return_value = 'nova-compute/2'
        with patch_open() as (_open, _file):
            _file.readlines = MagicMock()
            _file.write = MagicMock()
            _file.readlines.return_value = AUTHORIZED_KEYS.split('\n')
            utils.ssh_compute_remove()
            _file.write.assert_called_with(keys_removed)
