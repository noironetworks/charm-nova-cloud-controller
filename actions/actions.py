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
import charmhelpers.contrib.openstack.utils as ch_utils
import hooks.nova_cc_utils as utils
import hooks.nova_cc_hooks as ncc_hooks


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


def clear_unit_knownhost_cache(args):
    """Clear the knownhost cache for a unit (or all units), and then refresh
    the knownhosts, and potentially set the relation data for the associated
    service.

    If the target param doesn't match any unit or service, then the action does
    nothing.
    """
    target = hookenv.action_get('target')
    hookenv.action_set({
        "units-updated": clear_knownhost_cache(target)
    })


def clear_knownhost_cache(target):
    """Clear the known host cache for a target, rescan the affected units,
    and then update the knownhosts file for the affected service(s) and set the
    appropriate relation data.

    Examples of target are:
      - "" = all services, all units (clear all the caches)
      - "aservice" = clear all the units' caches on 'aservice'
      - "aservice/4" = just clear this specific unit and update the relation on
        that service.

    Note that if target doesn't match anything, then the function takes no
    action and no Exception is raised.

    :param target: The target to clear.
    :type target: str
    :returns: a list of units that were affected.
    :rtype: List[Dict[str, str]]
    """
    affected_units = []

    parts = target.split('/', 1)
    target_service = parts[0]
    is_unit = len(parts) > 1

    for r_id in hookenv.relation_ids('cloud-compute'):
        units = hookenv.related_units(r_id)
        if not units:
            continue
        service = utils.remote_service_from_unit(unit=units[0])
        if target_service and service != target_service:
            continue

        updated = False
        for unit in units:
            if is_unit and unit != target:
                continue
            private_address = hookenv.relation_get(
                attribute='private-address', unit=unit, rid=r_id)
            if private_address:
                utils.clear_hostset_cache_for(private_address)
                ncc_hooks.update_ssh_key(rid=r_id, unit=unit)
                updated = True
                affected_units.append({unit: private_address})

        # Note that this uses the last unit in the relation; that's ok as it's
        # only used to identify the service
        if updated:
            ncc_hooks.notify_ssh_keys_to_compute_units(rid=r_id, unit=unit)

    return affected_units


def sync_compute_availability_zones(args):
    """Sync the nova-compute Juju units' availability zones with the OpenStack
    hypervisors' availability zones."""
    # Due to python3 issues, we do a check here to see which version of
    # OpenStack is installed and gate the availability of the action on
    # that. See note below.
    release = ch_utils.CompareOpenStackReleases(
        ch_utils.os_release('nova-common'))
    if release < 'stein':
        msg = ('The sync_compute_availability_zones action is not available'
               'for the {} release.'.format(release))
        hookenv.action_fail(msg)
        return

    # Note (wolsen): There's a problem with the action script using only
    # python3 (/usr/bin/env python3) above, however on versions lower than
    # rocky, the python2 versions of the following python packages are
    # installed. The imports are moved to here to avoid causing actions
    # to fail outright.
    import hooks.nova_cc_context as ncc_context
    from keystoneauth1 import session
    from keystoneauth1.identity import v3
    from novaclient import client as nova_client
    from novaclient import exceptions as nova_exceptions

    ctxt = ncc_context.IdentityServiceContext()()
    if not ctxt:
        hookenv.action_fail("Identity service context cannot be generated")
        return

    keystone_auth = ctxt['keystone_authtoken']
    keystone_creds = {
        'auth_url': keystone_auth.get('auth_url'),
        'username': keystone_auth.get('username'),
        'password': keystone_auth.get('password'),
        'user_domain_name': keystone_auth.get('user_domain_name'),
        'project_domain_name': keystone_auth.get('project_domain_name'),
        'project_name': keystone_auth.get('project_name'),
    }
    keystone_session = session.Session(auth=v3.Password(**keystone_creds))
    client = nova_client.Client(2, session=keystone_session)
    output_str = ''
    for r_id in hookenv.relation_ids('cloud-compute'):
        units = hookenv.related_units(r_id)
        for unit in units:
            rel_data = hookenv.relation_get(rid=r_id, unit=unit)
            unit_az = rel_data.get('availability_zone')
            if not unit_az:
                continue
            aggregate_name = '{}_az'.format(unit_az)
            try:
                aggregate = client.aggregates.find(
                    name=aggregate_name, availability_zone=unit_az)
            except nova_exceptions.NotFound:
                aggregate = client.aggregates.create(
                    aggregate_name, availability_zone=unit_az)
            unit_ip = rel_data.get('private-address')
            hypervisor = client.hypervisors.find(host_ip=unit_ip)
            if hypervisor.hypervisor_hostname not in aggregate.hosts:
                client.aggregates.add_host(
                    aggregate, hypervisor.hypervisor_hostname)
            output_str += \
                "Hypervisor {} added to availability zone {}\n".format(
                    hypervisor.hypervisor_hostname, unit_az)
    hookenv.action_set({'output': output_str})


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {
    "pause": pause,
    "resume": resume,
    "archive-data": archive_data,
    "clear-unit-knownhost-cache": clear_unit_knownhost_cache,
    "sync-compute-availability-zones": sync_compute_availability_zones,
}


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
