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

import mock

from unit_tests.test_utils import (
    CharmTestCase,
    get_default_config,
)

__default_config = get_default_config()
# NOTE(freyes): the default 'distro' makes the test suite behave different
# depending on where it's being executed
__default_config['openstack-origin'] = ''

import hooks.nova_cc_utils as utils  # noqa
import actions.actions as actions


TO_PATCH = [
]


class PauseTestCase(CharmTestCase):

    def setUp(self):
        super(PauseTestCase, self).setUp(
            actions,
            [
                "hooks.nova_cc_utils.register_configs",
                "hooks.nova_cc_utils.pause_unit_helper"
            ])
        self.register_configs.return_value = 'test-config'

    def test_pauses_services(self):
        actions.pause([])
        self.pause_unit_helper.assert_called_once_with('test-config')


class ResumeTestCase(CharmTestCase):

    def setUp(self):
        super(ResumeTestCase, self).setUp(
            actions, [
                "hooks.nova_cc_utils.register_configs",
                "hooks.nova_cc_utils.resume_unit_helper"
            ])
        self.register_configs.return_value = 'test-config'

    def test_resumes_services(self):
        actions.resume([])
        self.resume_unit_helper.assert_called_once_with('test-config')


class ClearUnitKnownhostCacheTestCase(CharmTestCase):

    @staticmethod
    def _relation_get(attribute=None, unit=None, rid=None):
        return {
            'aservice/1': '10.0.0.1',
            'aservice/2': '10.0.0.2',
            'aservice/3': '10.0.0.3',
            'aservice/4': '10.0.0.4',
            'bservice/1': '10.0.1.1',
            'bservice/2': '10.0.1.2',
            'bservice/3': '10.0.1.3',
        }.get(unit)

    def setUp(self):
        super(ClearUnitKnownhostCacheTestCase, self).setUp(
            actions, [
                "charmhelpers.core.hookenv.action_get",
                "charmhelpers.core.hookenv.action_set",
                "charmhelpers.core.hookenv.relation_ids",
                "charmhelpers.core.hookenv.related_units",
                "charmhelpers.core.hookenv.relation_get",
                "hooks.nova_cc_utils.clear_hostset_cache_for",
                "hooks.nova_cc_hooks.update_ssh_key",
                "hooks.nova_cc_hooks.notify_ssh_keys_to_compute_units",
            ])
        self.relation_ids.return_value = ["r:1", "r:2"]
        self.related_units.side_effect = [
            ['aservice/1', 'aservice/2', 'aservice/3', 'aservice/4'],
            ['bservice/1', 'bservice/2', 'bservice/3'],
        ]
        self.relation_get.side_effect = \
            ClearUnitKnownhostCacheTestCase._relation_get

    def test_target_unit(self):
        self.action_get.return_value = 'aservice/2'
        actions.clear_unit_knownhost_cache([])
        self.action_set.assert_called_once_with({
            "units-updated": [{'aservice/2': '10.0.0.2'}]
        })
        self.clear_hostset_cache_for.assert_called_once_with('10.0.0.2')
        self.update_ssh_key.assert_called_once_with(rid="r:1",
                                                    unit="aservice/2")
        self.notify_ssh_keys_to_compute_units.assert_called_once_with(
            rid="r:1", unit="aservice/4")

    def test_target_service(self):
        self.action_get.return_value = 'bservice'
        actions.clear_unit_knownhost_cache([])
        self.action_set.assert_called_once_with({
            "units-updated": [
                {'bservice/1': '10.0.1.1'},
                {'bservice/2': '10.0.1.2'},
                {'bservice/3': '10.0.1.3'},
            ]
        })
        self.clear_hostset_cache_for.assert_has_calls(
            [mock.call('10.0.1.1'),
             mock.call('10.0.1.2'),
             mock.call('10.0.1.3')])
        self.update_ssh_key.assert_has_calls(
            [mock.call(rid="r:2", unit="bservice/1"),
             mock.call(rid="r:2", unit="bservice/2"),
             mock.call(rid="r:2", unit="bservice/3")])
        self.notify_ssh_keys_to_compute_units.assert_has_calls(
            [mock.call(rid="r:2", unit="bservice/3")])

    def test_target_all(self):
        self.action_get.return_value = ''
        actions.clear_unit_knownhost_cache([])
        self.action_set.assert_called_once_with({
            "units-updated": [
                {'aservice/1': '10.0.0.1'},
                {'aservice/2': '10.0.0.2'},
                {'aservice/3': '10.0.0.3'},
                {'aservice/4': '10.0.0.4'},
                {'bservice/1': '10.0.1.1'},
                {'bservice/2': '10.0.1.2'},
                {'bservice/3': '10.0.1.3'},
            ]
        })
        # check both services were updated; that'll imply the other calls were
        # made.
        self.notify_ssh_keys_to_compute_units.assert_has_calls(
            [mock.call(rid="r:1", unit="aservice/4"),
             mock.call(rid="r:2", unit="bservice/3")])


class MainTestCase(CharmTestCase):

    def setUp(self):
        super(MainTestCase, self).setUp(
            actions,
            [
                "charmhelpers.core.hookenv.action_fail",
                "hooks.nova_cc_utils.register_configs",
            ])
        self.register_configs.return_value = 'test-config'

    def test_invokes_action(self):
        dummy_calls = []

        def dummy_action(args):
            dummy_calls.append(True)

        with mock.patch.dict(actions.ACTIONS, {"foo": dummy_action}):
            actions.main(["foo"])
        self.assertEqual(dummy_calls, [True])

    def test_unknown_action(self):
        """Unknown actions aren't a traceback."""
        exit_string = actions.main(["foo"])
        self.assertEqual("Action foo undefined", exit_string)

    def test_failing_action(self):
        """Actions which traceback trigger action_fail() calls."""
        dummy_calls = []

        self.action_fail.side_effect = dummy_calls.append

        def dummy_action(args):
            raise ValueError("uh oh")

        with mock.patch.dict(actions.ACTIONS, {"foo": dummy_action}):
            actions.main(["foo"])
        self.assertEqual(dummy_calls, ["uh oh"])
