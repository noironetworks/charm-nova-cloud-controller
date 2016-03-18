import mock

with mock.patch('charmhelpers.core.hookenv.config') as config:
    config.return_value = 'nova'
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

from test_utils import (
    CharmTestCase
)

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
