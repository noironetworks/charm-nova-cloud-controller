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

from test_utils import (
    CharmTestCase,
    get_default_config,
)

__default_config = get_default_config()
# NOTE(freyes): the default 'distro' makes the test suite behave different
# depending on where it's being executed
__default_config['openstack-origin'] = ''

with mock.patch('charmhelpers.core.hookenv.config') as config:
    with mock.patch('charmhelpers.contrib.openstack.utils.get_os_codename_package'):  # noqa
        # this makes the config behave more similar to the real config()
        config.side_effect = lambda k: __default_config.get(k)

        import nova_cc_utils as utils  # noqa

# Need to do some early patching to get the module loaded.
_reg = utils.register_configs
_map = utils.restart_map

utils.register_configs = mock.MagicMock()
utils.restart_map = mock.MagicMock()

with mock.patch('nova_cc_utils.guard_map') as gmap:
    with mock.patch('charmhelpers.core.hookenv.config') as config:
        config.return_value = False
        gmap.return_value = {}
        import actions

# Unpatch it now that its loaded.
utils.register_configs = _reg
utils.restart_map = _map

TO_PATCH = [
]


class PauseTestCase(CharmTestCase):

    def setUp(self):
        super(PauseTestCase, self).setUp(
            actions, ["register_configs", "pause_unit_helper"])
        self.register_configs.return_value = 'test-config'

    def test_pauses_services(self):
        actions.pause([])
        self.pause_unit_helper.assert_called_once_with('test-config')


class ResumeTestCase(CharmTestCase):

    def setUp(self):
        super(ResumeTestCase, self).setUp(
            actions, ["register_configs", "resume_unit_helper"])
        self.register_configs.return_value = 'test-config'

    def test_resumes_services(self):
        actions.resume([])
        self.resume_unit_helper.assert_called_once_with('test-config')


class MainTestCase(CharmTestCase):

    def setUp(self):
        super(MainTestCase, self).setUp(actions, ["register_configs",
                                                  "action_fail"])
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
