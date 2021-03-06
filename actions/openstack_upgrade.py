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


import charmhelpers.contrib.openstack.utils as ch_utils
import charmhelpers.core.hookenv as hookenv
import hooks.nova_cc_utils as utils
import hooks.nova_cc_hooks as hooks


def openstack_upgrade():
    """Upgrade packages to config-set Openstack version.

    If the charm was installed from source we cannot upgrade it.
    For backwards compatibility a config flag must be set for this
    code to run, otherwise a full service level upgrade will fire
    on config-changed."""

    # If attempting to upgrade from Stein->Train, block until Placement
    # charm is related. Status is set in check_optional_relations().
    release = ch_utils.os_release('nova-common')
    cmp_os_release = ch_utils.CompareOpenStackReleases(release)
    if (cmp_os_release == 'stein' and not hookenv.relation_ids('placement')):
        return

    if (ch_utils.do_action_openstack_upgrade('nova-common',
                                             utils.do_openstack_upgrade,
                                             hooks.CONFIGS)):
        for rid in hookenv.relation_ids('neutron-api'):
            hooks.neutron_api_relation_joined(rid=rid, remote_restart=True)
        # NOTE(thedac): Force re-fire of shared-db joined hook
        # to ensure that nova_api database is setup if required.
        for r_id in hookenv.relation_ids('shared-db'):
            hooks.db_joined(relation_id=r_id)
        hooks.config_changed()


if __name__ == '__main__':
    hooks.resolve_CONFIGS()
    openstack_upgrade()
