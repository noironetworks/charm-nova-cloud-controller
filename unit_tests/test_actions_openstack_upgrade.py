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

from mock import patch
from unit_tests.test_utils import CharmTestCase

import actions.openstack_upgrade as openstack_upgrade


TO_PATCH = [
    'charmhelpers.core.hookenv.relation_ids',
    'hooks.nova_cc_hooks.config_changed',
    'hooks.nova_cc_hooks.db_joined',
    'hooks.nova_cc_hooks.neutron_api_relation_joined',
    'hooks.nova_cc_utils.do_openstack_upgrade',
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
