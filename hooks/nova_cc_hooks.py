#!/usr/bin/python
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
import shutil
import sys
import uuid

from subprocess import (
    check_call,
)

from urlparse import urlparse

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    charm_dir,
    is_leader,
    is_relation_made,
    log,
    local_unit,
    DEBUG,
    WARNING,
    relation_get,
    relation_ids,
    relation_set,
    related_units,
    open_port,
    unit_get,
    status_set,
)

from charmhelpers.core.host import (
    service_pause,
    service_reload,
    service_resume,
)

from charmhelpers.fetch import (
    apt_install,
    add_source,
    apt_update,
    filter_installed_packages
)

from charmhelpers.contrib.openstack.utils import (
    config_value_changed,
    configure_installation_source,
    openstack_upgrade_available,
    os_release,
    sync_db_with_multi_ipv6_addresses,
    pausable_restart_on_change as restart_on_change,
    is_unit_paused_set,
    CompareOpenStackReleases,
)

from charmhelpers.contrib.openstack.neutron import (
    network_manager,
)

from nova_cc_context import (
    NeutronAPIContext,
    NovaCellContext,
)

from charmhelpers.contrib.peerstorage import (
    peer_retrieve,
    peer_echo,
)

from nova_cc_utils import (
    add_hosts_to_cell,
    auth_token_config,
    determine_endpoints,
    determine_packages,
    determine_ports,
    disable_package_apache_site,
    do_openstack_upgrade,
    is_api_ready,
    is_cellv2_init_ready,
    keystone_ca_cert_b64,
    migrate_nova_databases,
    placement_api_enabled,
    save_script_rc,
    services,
    ssh_compute_add,
    ssh_compute_remove,
    ssh_known_hosts_lines,
    ssh_authorized_keys_lines,
    register_configs,
    restart_map,
    update_cell_database,
    NOVA_CONF,
    console_attributes,
    service_guard,
    guard_map,
    setup_ipv6,
    is_db_initialised,
    assess_status,
    update_aws_compat_services,
    serial_console_settings,
)

from charmhelpers.contrib.hahelpers.cluster import (
    get_hacluster_config,
    https,
    is_clustered,
)

from charmhelpers.contrib.openstack.ha.utils import (
    update_dns_ha_resource_params,
)

from charmhelpers.payload.execd import execd_preinstall

from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN,
    resolve_address,
)

from charmhelpers.contrib.network.ip import (
    format_ipv6_addr,
    get_iface_for_address,
    get_netmask_for_address,
    is_ipv6,
    get_relation_ip,
)

from charmhelpers.contrib.openstack.cert_utils import (
    get_certificate_request,
    process_certificates,
)

from charmhelpers.contrib.openstack.context import ADDRESS_TYPES

from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.hardening.harden import harden

try:
    FileNotFoundError
except NameError:
    # python3 compatibility
    FileNotFoundError = OSError

hooks = Hooks()
CONFIGS = register_configs()
COLO_CONSOLEAUTH = 'inf: res_nova_consoleauth grp_nova_vips'
AGENT_CONSOLEAUTH = 'ocf:openstack:nova-consoleauth'
AGENT_CA_PARAMS = 'op monitor interval="5s"'


def leader_init_db_if_ready(skip_acl_check=False, skip_cells_restarts=False,
                            db_rid=None, unit=None):
    """Initialise db if leader and db not yet intialised.

    NOTE: must be called from database context.
    """
    if not is_leader():
        log("Not leader - skipping db init", level=DEBUG)
        return

    if is_db_initialised():
        log("Database already initialised - skipping db init", level=DEBUG)
        return

    # Bugs 1353135 & 1187508. Dbs can appear to be ready before the units
    # acl entry has been added. So, if the db supports passing a list of
    # permitted units then check if we're in the list.
    allowed_units = relation_get('nova_allowed_units', rid=db_rid, unit=unit)
    if skip_acl_check or (allowed_units and local_unit() in
                          allowed_units.split()):
        status_set('maintenance', 'Running nova db migration')
        migrate_nova_databases()
        log('Triggering remote cloud-compute restarts.')
        [compute_joined(rid=rid, remote_restart=True)
            for rid in relation_ids('cloud-compute')]
        log('Triggering remote neutron-network-service restarts.')
        [quantum_joined(rid=rid, remote_restart=True)
            for rid in relation_ids('quantum-network-service')]
        if not skip_cells_restarts:
            log('Triggering remote cell restarts.')
            [nova_cell_relation_joined(rid=rid, remote_restart=True)
             for rid in relation_ids('cell')]
    else:
        log('allowed_units either not presented, or local unit '
            'not in acl list: %s' % repr(allowed_units))


def leader_init_db_if_ready_allowed_units():
    """Loop through all related db units and attempt to initialize db

    By looping through all related db units, the relation ID and unit can
    be passed to leader_init_db_if_ready(), enabling use of allowed_units
    to determine if this nova-cc unit is allowed to perform db init.
    """
    rels = ['shared-db']
    for rname in rels:
        for rid in relation_ids(rname):
            for unit in related_units(rid):
                leader_init_db_if_ready(db_rid=rid, unit=unit)


def update_cell_db_if_ready(skip_acl_check=False, db_rid=None, unit=None):
    """Update the cells db if leader and db's are already intialised"""
    if not is_leader():
        return

    if not is_db_initialised():
        log("Database not initialised - skipping cell db update", level=DEBUG)
        return

    if not is_cellv2_init_ready():
        return

    allowed_units = relation_get('nova_allowed_units', rid=db_rid, unit=unit)
    if skip_acl_check or (allowed_units and local_unit() in
                          allowed_units.split()):
        update_cell_database()
    else:
        log('allowed_units either not presented, or local unit '
            'not in acl list: %s' % repr(allowed_units))


def update_cell_db_if_ready_allowed_units():
    """Loop through all related db units and attempt to update cell db

    By looping through all related db units, the relation ID and unit can
    be passed to update_cell_db_if_ready(), enabling use of allowed_units
    to determine if this nova-cc unit is allowed to perform db updates.
    """
    rels = ['shared-db']
    for rname in rels:
        for rid in relation_ids(rname):
            for unit in related_units(rid):
                update_cell_db_if_ready(db_rid=rid, unit=unit)


@hooks.hook('install.real')
@harden()
def install():
    status_set('maintenance', 'Executing pre-install')
    execd_preinstall()
    configure_installation_source(config('openstack-origin'))

    status_set('maintenance', 'Installing apt packages')
    apt_update()
    apt_install(determine_packages(), fatal=True)

    opt = ['--option=Dpkg::Options::=--force-confdef' ,'--option=Dpkg::Options::=--force-confold']
    if config('aci-repo'):
       if config('aci-repo-key'):
           add_source(config('aci-repo'), key=config('aci-repo-key'))
       else:
           add_source(config('aci-repo'))
           opt.append('--allow-unauthenticated')
       apt_update()

    if config('enable-sriov-nic-selection'):
        apt_install(['python-nova-sriov-nics'], options=opt, fatal=True)

    if placement_api_enabled():
        disable_package_apache_site()

    _files = os.path.join(charm_dir(), 'files')
    if os.path.isdir(_files):
        for f in os.listdir(_files):
            f = os.path.join(_files, f)
            if os.path.isfile(f):
                log('Installing %s to /usr/bin' % f)
                shutil.copy2(f, '/usr/bin')
    [open_port(port) for port in determine_ports()]
    msg = 'Disabling services into db relation joined'
    log(msg)
    status_set('maintenance', msg)
    if not is_unit_paused_set():
        for svc in services():
            service_pause(svc)
    else:
        log('Unit is in paused state, not issuing stop/pause to all services')


@hooks.hook('config-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map(), stopstart=True)
@harden()
def config_changed():
    # neutron-server runs if < juno. Neutron-server creates mysql tables
    # which will subsequently cause db migrations to fail if >= juno.
    # Disable neutron-server if >= juno
    if CompareOpenStackReleases(os_release('nova-common')) >= 'juno':
        try:
            service_pause('neutron-server')
        except ValueError:
            # neutron-server service not installed, ignore.
            pass
    if config('prefer-ipv6'):
        status_set('maintenance', 'configuring ipv6')
        setup_ipv6()
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'),
                                          relation_prefix='nova')

    global CONFIGS
    if not config('action-managed-upgrade'):
        if openstack_upgrade_available('nova-common'):
            status_set('maintenance', 'Running openstack upgrade')
            do_openstack_upgrade(CONFIGS)
            [neutron_api_relation_joined(rid=rid, remote_restart=True)
                for rid in relation_ids('neutron-api')]
            # NOTE(jamespage): Force re-fire of shared-db joined hook
            # to ensure that nova_api database is setup if required.
            [db_joined(relation_id=r_id)
                for r_id in relation_ids('shared-db')]

    save_script_rc()
    configure_https()
    CONFIGS.write_all()

    # NOTE(jamespage): deal with any changes to the console and serial
    #                  console configuration options
    filtered = filter_installed_packages(determine_packages())
    if filtered:
        apt_install(filtered, fatal=True)

    opt = ['--option=Dpkg::Options::=--force-confdef' ,'--option=Dpkg::Options::=--force-confold']
    if config('aci-repo'):
       if config('aci-repo-key'):
           add_source(config('aci-repo'), key=config('aci-repo-key'))
       else:
           add_source(config('aci-repo'))
           opt.append('--allow-unauthenticated')
       apt_update()

    if config('enable-sriov-nic-selection'):
        apt_install(['python-nova-sriov-nics'], options=opt, fatal=True)


    for rid in relation_ids('quantum-network-service'):
        quantum_joined(rid=rid)
    for r_id in relation_ids('identity-service'):
        identity_joined(rid=r_id)
    [cluster_joined(rid) for rid in relation_ids('cluster')]
    [compute_joined(rid=rid) for rid in relation_ids('cloud-compute')]

    update_nrpe_config()

    # If the region value has changed, notify the cloud-compute relations
    # to ensure the value is propagated to the compute nodes.
    if config_value_changed('region'):
        for rid in relation_ids('cloud-compute'):
            for unit in related_units(rid):
                compute_changed(rid, unit)

    update_nova_consoleauth_config()
    update_aws_compat_services()


@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'), vhost=config('rabbit-vhost'))


@hooks.hook('amqp-relation-changed')
@hooks.hook('amqp-relation-departed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def amqp_changed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write(NOVA_CONF)
    leader_init_db_if_ready_allowed_units()
    # db init for cells v2 requires amqp transport_url and db connections
    # to be set in nova.conf, so we attempt db init in here as well as the
    # db relation-changed hooks.
    update_cell_db_if_ready_allowed_units()
    [nova_cell_relation_joined(rid=rid)
        for rid in relation_ids('cell')]

    for r_id in relation_ids('nova-api'):
        nova_api_relation_joined(rid=r_id)

    # NOTE: trigger restart on nova-api-metadata on
    #       neutron-gateway units once nova-cc has working
    #       amqp connection (avoiding service down on n-gateway)
    for rid in relation_ids('quantum-network-service'):
        quantum_joined(rid=rid, remote_restart=True)


@hooks.hook('shared-db-relation-joined')
def db_joined(relation_id=None):
    cmp_os_release = CompareOpenStackReleases(os_release('nova-common'))
    if config('prefer-ipv6'):
        sync_db_with_multi_ipv6_addresses(config('database'),
                                          config('database-user'),
                                          relation_prefix='nova')

        if cmp_os_release >= 'mitaka':
            # NOTE: mitaka uses a second nova-api database as well
            sync_db_with_multi_ipv6_addresses('nova_api',
                                              config('database-user'),
                                              relation_prefix='novaapi')

        if cmp_os_release >= 'ocata':
            # NOTE: ocata requires cells v2
            sync_db_with_multi_ipv6_addresses('nova_cell0',
                                              config('database-user'),
                                              relation_prefix='novacell0')
    else:
        # Avoid churn check for access-network early
        access_network = None
        for unit in related_units(relid=relation_id):
            access_network = relation_get(rid=relation_id, unit=unit,
                                          attribute='access-network')
            if access_network:
                break
        host = get_relation_ip('shared-db', cidr_network=access_network)

        relation_set(nova_database=config('database'),
                     nova_username=config('database-user'),
                     nova_hostname=host,
                     relation_id=relation_id)

        if cmp_os_release >= 'mitaka':
            # NOTE: mitaka uses a second nova-api database as well
            relation_set(novaapi_database='nova_api',
                         novaapi_username=config('database-user'),
                         novaapi_hostname=host,
                         relation_id=relation_id)

        if cmp_os_release >= 'ocata':
            # NOTE: ocata requires cells v2
            relation_set(novacell0_database='nova_cell0',
                         novacell0_username=config('database-user'),
                         novacell0_hostname=host,
                         relation_id=relation_id)


@hooks.hook('shared-db-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def db_changed():
    if 'shared-db' not in CONFIGS.complete_contexts():
        log('shared-db relation incomplete. Peer not ready?')
        return

    CONFIGS.write_all()
    leader_init_db_if_ready()
    # db init for cells v2 requires amqp transport_url and db connections to
    # be set in nova.conf, so we attempt db init in here as well as the
    # amqp-relation-changed hook.
    update_cell_db_if_ready()


@hooks.hook('image-service-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def image_service_changed():
    if 'image-service' not in CONFIGS.complete_contexts():
        log('image-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write(NOVA_CONF)
    # TODO: special case config flag for essex (strip protocol)

    for r_id in relation_ids('nova-api'):
        nova_api_relation_joined(rid=r_id)


@hooks.hook('identity-service-relation-joined')
def identity_joined(rid=None):
    if config('vip') and not is_clustered():
        log('Defering registration until clustered', level=DEBUG)
        return

    public_url = canonical_url(CONFIGS, PUBLIC)
    internal_url = canonical_url(CONFIGS, INTERNAL)
    admin_url = canonical_url(CONFIGS, ADMIN)
    relation_set(
        relation_id=rid,
        **determine_endpoints(public_url,
                              internal_url,
                              admin_url))


@hooks.hook('identity-service-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def identity_changed():
    if 'identity-service' not in CONFIGS.complete_contexts():
        log('identity-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write('/etc/nova/api-paste.ini')
    CONFIGS.write(NOVA_CONF)
    [compute_joined(rid) for rid in relation_ids('cloud-compute')]
    [quantum_joined(rid) for rid in relation_ids('quantum-network-service')]
    [nova_vmware_relation_joined(rid) for rid in relation_ids('nova-vmware')]
    [neutron_api_relation_joined(rid) for rid in relation_ids('neutron-api')]
    configure_https()

    for r_id in relation_ids('nova-api'):
        nova_api_relation_joined(rid=r_id)


@hooks.hook('nova-volume-service-relation-joined',
            'cinder-volume-service-relation-joined')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def volume_joined():
    CONFIGS.write(NOVA_CONF)
    # kick identity_joined() to publish possibly new nova-volume endpoint.
    [identity_joined(rid) for rid in relation_ids('identity-service')]


def _auth_config():
    '''Grab all KS auth token config from api-paste.ini, or return empty {}'''
    ks_auth_host = auth_token_config('auth_host')
    if not ks_auth_host:
        # if there is no auth_host set, identity-service changed hooks
        # have not fired, yet.
        return {}
    cfg = {
        'auth_host': ks_auth_host,
        'auth_port': auth_token_config('auth_port'),
        'auth_protocol': auth_token_config('auth_protocol'),
        'service_protocol': auth_token_config('service_protocol'),
        'service_port': auth_token_config('service_port'),
        'service_username': auth_token_config('admin_user'),
        'service_password': auth_token_config('admin_password'),
        'service_tenant_name': auth_token_config('admin_tenant_name'),
        'auth_uri': auth_token_config('auth_uri'),
        # quantum-gateway interface deviates a bit.
        'keystone_host': ks_auth_host,
        'service_tenant': auth_token_config('admin_tenant_name'),
        # add api version if found
        'api_version': auth_token_config('api_version') or '2.0',
    }
    return cfg


def save_novarc():
    auth = _auth_config()
    # XXX hard-coded http
    ks_url = '%s://%s:%s/v%s' % (auth['auth_protocol'],
                                 auth['auth_host'],
                                 auth['auth_port'],
                                 auth['api_version'])
    with open('/etc/quantum/novarc', 'wb') as out:
        out.write('export OS_USERNAME=%s\n' % auth['service_username'])
        out.write('export OS_PASSWORD=%s\n' % auth['service_password'])
        out.write('export OS_TENANT_NAME=%s\n' % auth['service_tenant_name'])
        out.write('export OS_AUTH_URL=%s\n' % ks_url)
        out.write('export OS_REGION_NAME=%s\n' % config('region'))


def neutron_settings():
    neutron_settings = {}
    if is_relation_made('neutron-api', 'neutron-plugin'):
        neutron_api_info = NeutronAPIContext()()
        neutron_settings.update({
            # XXX: Rename these relations settings?
            'quantum_plugin': neutron_api_info['neutron_plugin'],
            'region': config('region'),
            'quantum_security_groups':
            neutron_api_info['neutron_security_groups'],
            'quantum_url': neutron_api_info['neutron_url'],
        })
        neutron_url = urlparse(neutron_settings['quantum_url'])
        neutron_settings['quantum_host'] = neutron_url.hostname
        neutron_settings['quantum_port'] = neutron_url.port
    return neutron_settings


def keystone_compute_settings():
    ks_auth_config = _auth_config()
    rel_settings = {}

    if network_manager() == 'neutron':
        if ks_auth_config:
            rel_settings.update(ks_auth_config)
        rel_settings.update(neutron_settings())
    ks_ca = keystone_ca_cert_b64()
    if ks_auth_config and ks_ca:
        rel_settings['ca_cert'] = ks_ca
    return rel_settings


def console_settings():
    rel_settings = {}
    proto = console_attributes('protocol')
    if not proto:
        return {}
    rel_settings['console_keymap'] = config('console-keymap')
    rel_settings['console_access_protocol'] = proto

    console_ssl = False
    if config('console-ssl-cert') and config('console-ssl-key'):
        console_ssl = True

    if config('console-proxy-ip') == 'local':
        if console_ssl:
            address = resolve_address(endpoint_type=PUBLIC)
            address = format_ipv6_addr(address) or address
            proxy_base_addr = 'https://%s' % address
        else:
            # canonical_url will only return 'https:' if API SSL are enabled.
            proxy_base_addr = canonical_url(CONFIGS, PUBLIC)
    else:
        if console_ssl or https():
            schema = "https"
        else:
            schema = "http"

        proxy_base_addr = "%s://%s" % (schema, config('console-proxy-ip'))

    if proto == 'vnc':
        protocols = ['novnc', 'xvpvnc']
    else:
        protocols = [proto]
    for _proto in protocols:
        rel_settings['console_proxy_%s_address' % (_proto)] = \
            "%s:%s%s" % (proxy_base_addr,
                         console_attributes('proxy-port', proto=_proto),
                         console_attributes('proxy-page', proto=_proto))
        rel_settings['console_proxy_%s_host' % (_proto)] = \
            urlparse(proxy_base_addr).hostname
        rel_settings['console_proxy_%s_port' % (_proto)] = \
            console_attributes('proxy-port', proto=_proto)

    return rel_settings


@hooks.hook('cloud-compute-relation-joined')
def compute_joined(rid=None, remote_restart=False):
    cons_settings = console_settings()
    relation_set(relation_id=rid, **cons_settings)
    rel_settings = {
        'network_manager': network_manager(),
        'volume_service': 'cinder',
        # (comment from bash vers) XXX Should point to VIP if clustered, or
        # this may not even be needed.
        'ec2_host': unit_get('private-address'),
        'region': config('region'),
    }
    rel_settings.update(serial_console_settings())
    # update relation setting if we're attempting to restart remote
    # services
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())

    rel_settings.update(keystone_compute_settings())
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('cloud-compute-relation-changed')
def compute_changed(rid=None, unit=None):
    for r_id in relation_ids('nova-api'):
        nova_api_relation_joined(rid=r_id)

    rel_settings = relation_get(rid=rid, unit=unit)
    if not rel_settings.get('region', None) == config('region'):
        relation_set(relation_id=rid, region=config('region'))

    if is_leader() and is_cellv2_init_ready() and is_db_initialised():
        add_hosts_to_cell()

    if 'migration_auth_type' not in rel_settings:
        return
    if rel_settings['migration_auth_type'] == 'ssh':
        status_set('maintenance', 'configuring live migration')
        key = rel_settings.get('ssh_public_key')
        if not key:
            log('SSH migration set but peer did not publish key.')
            return
        ssh_compute_add(key, rid=rid, unit=unit)
        index = 0
        for line in ssh_known_hosts_lines(unit=unit):
            relation_set(
                relation_id=rid,
                relation_settings={
                    'known_hosts_{}'.format(index): line})
            index += 1
        relation_set(relation_id=rid, known_hosts_max_index=index)
        index = 0
        for line in ssh_authorized_keys_lines(unit=unit):
            relation_set(
                relation_id=rid,
                relation_settings={
                    'authorized_keys_{}'.format(index): line})
            index += 1
        relation_set(relation_id=rid, authorized_keys_max_index=index)
    if 'nova_ssh_public_key' not in rel_settings:
        return
    if rel_settings['nova_ssh_public_key']:
        ssh_compute_add(rel_settings['nova_ssh_public_key'],
                        rid=rid, unit=unit, user='nova')
        index = 0
        for line in ssh_known_hosts_lines(unit=unit, user='nova'):
            relation_set(
                relation_id=rid,
                relation_settings={
                    '{}_known_hosts_{}'.format(
                        'nova',
                        index): line})
            index += 1
        relation_set(
            relation_id=rid,
            relation_settings={
                '{}_known_hosts_max_index'.format('nova'): index})
        index = 0
        for line in ssh_authorized_keys_lines(unit=unit, user='nova'):
            relation_set(
                relation_id=rid,
                relation_settings={
                    '{}_authorized_keys_{}'.format(
                        'nova',
                        index): line})
            index += 1
        relation_set(
            relation_id=rid,
            relation_settings={
                '{}_authorized_keys_max_index'.format('nova'): index})


@hooks.hook('cloud-compute-relation-departed')
def compute_departed():
    ssh_compute_remove(public_key=relation_get('ssh_public_key'))


@hooks.hook('neutron-network-service-relation-joined',
            'quantum-network-service-relation-joined')
def quantum_joined(rid=None, remote_restart=False):
    rel_settings = neutron_settings()

    # inform quantum about local keystone auth config
    ks_auth_config = _auth_config()
    rel_settings.update(ks_auth_config)

    # must pass the keystone CA cert, if it exists.
    ks_ca = keystone_ca_cert_b64()
    if ks_auth_config and ks_ca:
        rel_settings['ca_cert'] = ks_ca

    # update relation setting if we're attempting to restart remote
    # services
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())

    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('cluster-relation-joined')
def cluster_joined(relation_id=None):
    settings = {}

    for addr_type in ADDRESS_TYPES:
        address = get_relation_ip(
            addr_type,
            cidr_network=config('os-{}-network'.format(addr_type)))
        if address:
            settings['{}-address'.format(addr_type)] = address

    settings['private-address'] = get_relation_ip('cluster')

    relation_set(relation_id=relation_id, relation_settings=settings)


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed',
            'leader-settings-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map(), stopstart=True)
def cluster_changed():
    CONFIGS.write_all()
    if relation_ids('cluster'):
        peer_echo(includes=['dbsync_state'])
        dbsync_state = peer_retrieve('dbsync_state')
        if dbsync_state == 'complete':
            if not is_unit_paused_set():
                for svc in services():
                    service_resume(svc)
            else:
                log('Unit is in paused state, not issuing start/resume to all '
                    'services')
        else:
            if not is_unit_paused_set():
                log('Database sync not ready. Shutting down services')
                for svc in services():
                    service_pause(svc)
            else:
                log('Database sync not ready. Would shut down services but '
                    'unit is in paused state, not issuing stop/pause to all '
                    'services')


@hooks.hook('ha-relation-joined')
def ha_joined(relation_id=None):
    cluster_config = get_hacluster_config()
    resources = {
        'res_nova_haproxy': 'lsb:haproxy',
    }
    resource_params = {
        'res_nova_haproxy': 'op monitor interval="5s"',
    }
    init_services = {
        'res_nova_haproxy': 'haproxy'
    }
    clones = {
        'cl_nova_haproxy': 'res_nova_haproxy'
    }
    colocations = {}

    if config('dns-ha'):
        update_dns_ha_resource_params(relation_id=relation_id,
                                      resources=resources,
                                      resource_params=resource_params)
    else:
        vip_group = []
        for vip in cluster_config['vip'].split():
            if is_ipv6(vip):
                res_nova_vip = 'ocf:heartbeat:IPv6addr'
                vip_params = 'ipv6addr'
            else:
                res_nova_vip = 'ocf:heartbeat:IPaddr2'
                vip_params = 'ip'

            iface = (get_iface_for_address(vip) or
                     config('vip_iface'))
            netmask = (get_netmask_for_address(vip) or
                       config('vip_cidr'))

            if iface is not None:
                vip_key = 'res_nova_{}_vip'.format(iface)
                if vip_key in vip_group:
                    if vip not in resource_params[vip_key]:
                        vip_key = '{}_{}'.format(vip_key, vip_params)
                    else:
                        log("Resource '%s' (vip='%s') already exists in "
                            "vip group - skipping" % (vip_key, vip), WARNING)
                        continue

                resources[vip_key] = res_nova_vip
                resource_params[vip_key] = (
                    'params {ip}="{vip}" cidr_netmask="{netmask}"'
                    ' nic="{iface}"'.format(ip=vip_params,
                                            vip=vip,
                                            iface=iface,
                                            netmask=netmask)
                )
                vip_group.append(vip_key)

            if len(vip_group) >= 1:
                relation_set(groups={'grp_nova_vips': ' '.join(vip_group)})

        if (config('single-nova-consoleauth') and
                console_attributes('protocol')):
            colocations['vip_consoleauth'] = COLO_CONSOLEAUTH
            init_services['res_nova_consoleauth'] = 'nova-consoleauth'
            resources['res_nova_consoleauth'] = AGENT_CONSOLEAUTH
            resource_params['res_nova_consoleauth'] = AGENT_CA_PARAMS

    relation_set(relation_id=relation_id,
                 init_services=init_services,
                 corosync_bindiface=cluster_config['ha-bindiface'],
                 corosync_mcastport=cluster_config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones,
                 colocations=colocations)


@hooks.hook('ha-relation-changed')
def ha_changed():
    clustered = relation_get('clustered')
    if not clustered or clustered in [None, 'None', '']:
        log('ha_changed: hacluster subordinate not fully clustered.')
        return

    CONFIGS.write(NOVA_CONF)

    log('Cluster configured, notifying other services and updating '
        'keystone endpoint configuration')
    for rid in relation_ids('identity-service'):
        identity_joined(rid=rid)

    update_nova_consoleauth_config()


@hooks.hook('shared-db-relation-broken')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
def db_departed():
    CONFIGS.write_all()
    update_cell_db_if_ready(skip_acl_check=True)
    for r_id in relation_ids('cluster'):
        relation_set(relation_id=r_id, dbsync_state='incomplete')
    if not is_unit_paused_set():
        for svc in services():
            service_pause(svc)
    else:
        log('Unit is in paused state, not issuing stop/pause to all '
            'services')


@hooks.hook('amqp-relation-broken',
            'cinder-volume-service-relation-broken',
            'identity-service-relation-broken',
            'image-service-relation-broken',
            'nova-volume-service-relation-broken',
            'quantum-network-service-relation-broken')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
def relation_broken():
    CONFIGS.write_all()
    [nova_cell_relation_joined(rid=rid)
        for rid in relation_ids('cell')]


def configure_https():
    '''
    Enables SSL API Apache config if appropriate and kicks identity-service
    with any required api updates.
    '''
    # need to write all to ensure changes to the entire request pipeline
    # propagate (c-api, haprxy, apache)
    CONFIGS.write_all()
    if 'https' in CONFIGS.complete_contexts():
        cmd = ['a2ensite', 'openstack_https_frontend']
        check_call(cmd)
    else:
        cmd = ['a2dissite', 'openstack_https_frontend']
        check_call(cmd)

    # TODO: improve this by checking if local CN certs are available
    # first then checking reload status (see LP #1433114).
    if not is_unit_paused_set():
        service_reload('apache2', restart_on_failure=True)

    for rid in relation_ids('identity-service'):
        identity_joined(rid=rid)


@hooks.hook()
def nova_vmware_relation_joined(rid=None):
    rel_settings = {'network_manager': network_manager()}

    ks_auth = _auth_config()
    if ks_auth:
        rel_settings.update(ks_auth)
        rel_settings.update(neutron_settings())

    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('nova-vmware-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def nova_vmware_relation_changed():
    CONFIGS.write('/etc/nova/nova.conf')


@hooks.hook('upgrade-charm')
@harden()
def upgrade_charm():
    apt_install(filter_installed_packages(determine_packages()),
                fatal=True)
    opt = ['--option=Dpkg::Options::=--force-confdef' ,'--option=Dpkg::Options::=--force-confold']
    if config('aci-repo'):
       if config('aci-repo-key'):
           add_source(config('aci-repo'), key=config('aci-repo-key'))
       else:
           add_source(config('aci-repo'))
           opt.append('--allow-unauthenticated')
       apt_update()

    if config('enable-sriov-nic-selection'):
        apt_install(['python-nova-sriov-nics'], options=opt, fatal=True)

    for r_id in relation_ids('amqp'):
        amqp_joined(relation_id=r_id)
    for r_id in relation_ids('identity-service'):
        identity_joined(rid=r_id)
    for r_id in relation_ids('cloud-compute'):
        for unit in related_units(r_id):
            compute_changed(r_id, unit)
    for r_id in relation_ids('shared-db'):
        db_joined(relation_id=r_id)

    leader_init_db_if_ready_allowed_units()

    update_nrpe_config()
    update_nova_consoleauth_config()


# remote_restart is defaulted to true as nova-cells may have started the
# nova-cell process before the db migration was run so it will need a
# kick
@hooks.hook('cell-relation-joined')
def nova_cell_relation_joined(rid=None, remote_restart=True):
    rel_settings = {
        'nova_url': "%s:8774/v2" % canonical_url(CONFIGS, INTERNAL)
    }
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('cell-relation-changed')
@restart_on_change(restart_map())
def nova_cell_relation_changed():
    CONFIGS.write(NOVA_CONF)


def get_cell_type():
    cell_info = NovaCellContext()()
    if 'cell_type' in cell_info:
        return cell_info['cell_type']
    return None


@hooks.hook('neutron-api-relation-joined')
def neutron_api_relation_joined(rid=None, remote_restart=False):
    for id_rid in relation_ids('identity-service'):
        identity_joined(rid=id_rid)
    rel_settings = {
        'nova_url': canonical_url(CONFIGS, INTERNAL) + ":8774/v2"
    }
    if get_cell_type():
        rel_settings['cell_type'] = get_cell_type()
    if remote_restart:
        rel_settings['restart_trigger'] = str(uuid.uuid4())
    relation_set(relation_id=rid, **rel_settings)


@hooks.hook('neutron-api-relation-changed')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def neutron_api_relation_changed():
    CONFIGS.write(NOVA_CONF)
    for rid in relation_ids('cloud-compute'):
        compute_joined(rid=rid)
    for rid in relation_ids('quantum-network-service'):
        quantum_joined(rid=rid)


@hooks.hook('neutron-api-relation-broken')
@service_guard(guard_map(), CONFIGS,
               active=config('service-guard'))
@restart_on_change(restart_map())
def neutron_api_relation_broken():
    CONFIGS.write_all()
    for rid in relation_ids('cloud-compute'):
        compute_joined(rid=rid)
    for rid in relation_ids('quantum-network-service'):
        quantum_joined(rid=rid)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def update_nrpe_config():
    # python-dbus is used by check_upstart_job
    apt_install('python-dbus')
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.copy_nrpe_checks()
    nrpe.add_init_service_checks(nrpe_setup, services(), current_unit)
    nrpe.add_haproxy_checks(nrpe_setup, current_unit)
    nrpe_setup.write()


@hooks.hook('memcache-relation-joined')
def memcached_joined():
    """When memcache relation joins we want to set our private address as the
    spaces address rather than leaving it as the unit address.  This is to
    support network spaces in the memcached charm.
    """
    relation_set(
        relation_id=None,
        relation_settings={'private-address': get_relation_ip('memcache')})
    memcached_common()


@hooks.hook('memcache-relation-departed',
            'memcache-relation-changed',
            'memcache-relation-broken')
def memcached_other_hooks():
    memcached_common()


@restart_on_change(restart_map())
def memcached_common():
    CONFIGS.write(NOVA_CONF)


@hooks.hook('zeromq-configuration-relation-changed')
@restart_on_change(restart_map(), stopstart=True)
def zeromq_configuration_relation_changed():
    CONFIGS.write(NOVA_CONF)


def update_nova_consoleauth_config():
    """
    Configure nova-consoleauth pacemaker resources
    """
    relids = relation_ids('ha')
    if len(relids) == 0:
        log('Related to {} ha services'.format(len(relids)), level='DEBUG')
        ha_relid = None
        data = {}
    else:
        ha_relid = relids[0]
        data = relation_get(rid=ha_relid) or {}

    # initialize keys in case this is a new dict
    data.setdefault('delete_resources', [])
    for k in ['colocations', 'init_services', 'resources', 'resource_params']:
        data.setdefault(k, {})

    if config('single-nova-consoleauth') and console_attributes('protocol'):
        for item in ['vip_consoleauth', 'res_nova_consoleauth']:
            try:
                data['delete_resources'].remove(item)
            except ValueError:
                pass  # nothing to remove, we are good

        # the new pcmkr resources have to be added to the existing ones
        data['colocations']['vip_consoleauth'] = COLO_CONSOLEAUTH
        data['init_services']['res_nova_consoleauth'] = 'nova-consoleauth'
        data['resources']['res_nova_consoleauth'] = AGENT_CONSOLEAUTH
        data['resource_params']['res_nova_consoleauth'] = AGENT_CA_PARAMS

        for rid in relation_ids('ha'):
            relation_set(rid, **data)

        # nova-consoleauth will be managed by pacemaker, so stop it
        # and prevent it to be started again at boot. (LP: #1693629).
        if relation_ids('ha'):
            service_pause('nova-consoleauth')

    elif (not config('single-nova-consoleauth') and
          console_attributes('protocol')):
        for item in ['vip_consoleauth', 'res_nova_consoleauth']:
            if item not in data['delete_resources']:
                data['delete_resources'].append(item)

        # remove them from the rel, so they aren't recreated when the hook
        # is recreated
        data['colocations'].pop('vip_consoleauth', None)
        data['init_services'].pop('res_nova_consoleauth', None)
        data['resources'].pop('res_nova_consoleauth', None)
        data['resource_params'].pop('res_nova_consoleauth', None)

        for rid in relation_ids('ha'):
            relation_set(rid, **data)

        service_resume('nova-consoleauth')


def nova_api_relation_joined(rid=None):
    rel_data = {
        'nova-api-ready': 'yes' if is_api_ready(CONFIGS) else 'no'
    }
    relation_set(rid, **rel_data)


@hooks.hook('certificates-relation-joined')
def certs_joined(relation_id=None):
    relation_set(
        relation_id=relation_id,
        relation_settings=get_certificate_request())


@hooks.hook('certificates-relation-changed')
@restart_on_change(restart_map(), stopstart=True)
def certs_changed(relation_id=None, unit=None):
    process_certificates('nova', relation_id, unit)
    configure_https()


@hooks.hook('update-status')
@harden()
def update_status():
    log('Updating status.')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(CONFIGS)


if __name__ == '__main__':
    main()
