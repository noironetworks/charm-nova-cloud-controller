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

from mock import patch, MagicMock

os.environ['JUJU_UNIT_NAME'] = 'nova-cloud-controller'
with patch('charmhelpers.core.hookenv.config') as config:
    with patch('charmhelpers.contrib.openstack.utils.get_os_codename_package'):
        config.return_value = 'nova'
        import nova_cc_utils as utils  # noqa

_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = MagicMock()
utils.restart_map = MagicMock()

with patch('nova_cc_utils.guard_map') as gmap:
    with patch('charmhelpers.core.hookenv.config') as config:
        config.return_value = False
        gmap.return_value = {}
        import openstack_upgrade

utils.register_configs = _reg
utils.restart_map = _map

from test_utils import CharmTestCase

TO_PATCH = [
    'do_openstack_upgrade',
    'relation_ids',
    'neutron_api_relation_joined',
    'db_joined',
    'config_changed',
]


class TestNovaCCUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestNovaCCUpgradeActions, self).setUp(openstack_upgrade,
                                                    TO_PATCH)

    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_true(self, upgrade_avail,
                                    action_set, config):
        upgrade_avail.return_value = True
        config.return_value = True
        self.relation_ids.return_value = ['relid1']

        openstack_upgrade.openstack_upgrade()

        self.assertTrue(self.do_openstack_upgrade.called, config.mock_calls)
        self.neutron_api_relation_joined.assert_called_with(
            rid='relid1', remote_restart=True)
        self.db_joined.assert_called_with(relation_id='relid1')
        self.assertTrue(self.config_changed.called)

    @patch('charmhelpers.contrib.openstack.utils.config')
    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_openstack_upgrade_false(self, upgrade_avail,
                                     action_set, config):
        upgrade_avail.return_value = True
        config.return_value = False

        openstack_upgrade.openstack_upgrade()

        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.config_changed.called)
