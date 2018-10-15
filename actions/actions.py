#!/usr/bin/env python3
#
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
import sys

_path = os.path.dirname(os.path.realpath(__file__))
_root = os.path.abspath(os.path.join(_path, '..'))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)

_add_path(_root)

import charmhelpers.core.hookenv as hookenv
import hooks.nova_cc_utils as utils


def pause(args):
    """Pause the Ceilometer services.
    @raises Exception should the service fail to stop.
    """
    utils.pause_unit_helper(utils.register_configs())


def resume(args):
    """Resume the Ceilometer services.
    @raises Exception should the service fail to start."""
    utils.resume_unit_helper(utils.register_configs())


def archive_data(args):
    """Run data archival process
    @raises Exception should the archival fail"""
    hookenv.action_set({
        'archive-deleted-rows': utils.archive_deleted_rows(
            max_rows=hookenv.action_get('batch-size'))})


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {
    "pause": pause,
    "resume": resume,
    "archive-data": archive_data}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            hookenv.action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
