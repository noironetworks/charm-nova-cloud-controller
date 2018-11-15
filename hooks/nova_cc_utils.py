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

import base64
import collections
import configparser
import copy
import json
import os
import subprocess
from urllib.parse import urlparse
import uuid

import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.network.ip as ch_ip
import charmhelpers.contrib.openstack.context as ch_context
import charmhelpers.contrib.openstack.ip as ch_openstack_ip
import charmhelpers.contrib.openstack.templating as ch_templating
import charmhelpers.contrib.openstack.utils as ch_utils
import charmhelpers.contrib.peerstorage as ch_peerstorage
import charmhelpers.core.decorators as ch_decorators
import charmhelpers.core.hookenv as hookenv
import charmhelpers.core.host as ch_host
import charmhelpers.fetch as ch_fetch

import hooks.nova_cc_common as common
import hooks.nova_cc_context as nova_cc_context

TEMPLATES = 'templates/'

CLUSTER_RES = 'grp_nova_vips'

SHARED_METADATA_SECRET_KEY = 'shared-metadata-secret'

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'database': ['shared-db'],
    'messaging': ['amqp'],
    'identity': ['identity-service'],
    'image': ['image-service'],
    'compute': ['nova-compute', 'nova-cell-api'],
}

# removed from original: charm-helper-sh
BASE_PACKAGES = [
    'apache2',
    'haproxy',
    'libapache2-mod-wsgi',
    'python-keystoneclient',
    'python-mysqldb',
    'python-psycopg2',
    'python-psutil',
    'python-memcache',
    'uuid',
]

PY3_PACKAGES = [
    'libapache2-mod-wsgi-py3',
    'python3-nova',
    'python3-keystoneclient',
    'python3-psutil',
    'python3-six',
    'python3-memcache',
]

VERSION_PACKAGE = 'nova-common'

BASE_SERVICES = [
    'nova-api-ec2',
    'nova-api-os-compute',
    'nova-placement-api',
    'nova-objectstore',
    'nova-cert',
    'nova-scheduler',
    'nova-conductor',
]

AWS_COMPAT_SERVICES = ['nova-api-ec2', 'nova-objectstore']
SERVICE_BLACKLIST = {
    'liberty': AWS_COMPAT_SERVICES,
    'newton': ['nova-cert'],
}

# API_PORTS is now in nova_cc_common.py to break the circular dependency
# between nova_cc_utils.py and nova_cc_context.py

NOVA_CONF_DIR = "/etc/nova"
NEUTRON_CONF_DIR = "/etc/neutron"

NOVA_CONF = '%s/nova.conf' % NOVA_CONF_DIR
NOVA_API_PASTE = '%s/api-paste.ini' % NOVA_CONF_DIR
HAPROXY_CONF = '/etc/haproxy/haproxy.cfg'
APACHE_CONF = '/etc/apache2/sites-available/openstack_https_frontend'
APACHE_24_CONF = '/etc/apache2/sites-available/openstack_https_frontend.conf'
MEMCACHED_CONF = '/etc/memcached.conf'
WSGI_NOVA_PLACEMENT_API_CONF = \
    '/etc/apache2/sites-enabled/wsgi-openstack-api.conf'
PACKAGE_NOVA_PLACEMENT_API_CONF = \
    '/etc/apache2/sites-enabled/nova-placement-api.conf'
WSGI_NOVA_METADATA_API_CONF = \
    '/etc/apache2/sites-enabled/wsgi-openstack-metadata.conf'
VENDORDATA_FILE = '/etc/nova/vendor_data.json'


def resolve_services():
    _services = copy.deepcopy(BASE_SERVICES)
    os_rel = ch_utils.os_release('nova-common')
    cmp_os_release = ch_utils.CompareOpenStackReleases(os_rel)
    for release in SERVICE_BLACKLIST:
        if cmp_os_release >= release or hookenv.config('disable-aws-compat'):
            for service in SERVICE_BLACKLIST[release]:
                _services.remove(service)
    return _services


# _BASE_RESOURCE_MAP is a caching global that is set up by
# get_base_resource_map()
_BASE_RESOURCE_MAP = None


def get_base_resource_map():
    """Return the base resource map.  Note that it is cached in the
    _BASE_RESOURCE_MAP global.

    :returns: The base resource map
    :rtype: collections.OrderedDict
    """
    global _BASE_RESOURCE_MAP
    if _BASE_RESOURCE_MAP is None:
        _BASE_RESOURCE_MAP = collections.OrderedDict([
            (NOVA_CONF, {
                'services': resolve_services(),
                'contexts': [
                    ch_context.AMQPContext(ssl_dir=NOVA_CONF_DIR),
                    ch_context.SharedDBContext(
                        relation_prefix='nova',
                        ssl_dir=NOVA_CONF_DIR),
                    ch_context.OSConfigFlagContext(
                        charm_flag='nova-alchemy-flags',
                        template_flag='nova_alchemy_flags'),
                    ch_context.ImageServiceContext(),
                    ch_context.OSConfigFlagContext(),
                    ch_context.SubordinateConfigContext(
                        interface='nova-vmware',
                        service='nova',
                        config_file=NOVA_CONF),
                    ch_context.SyslogContext(),
                    ch_context.LogLevelContext(),
                    nova_cc_context.HAProxyContext(),
                    nova_cc_context.IdentityServiceContext(
                        service='nova',
                        service_user='nova'),
                    nova_cc_context.VolumeServiceContext(),
                    ch_context.ZeroMQContext(),
                    ch_context.NotificationDriverContext(),
                    nova_cc_context.NovaIPv6Context(),
                    nova_cc_context.NeutronCCContext(),
                    nova_cc_context.NovaConfigContext(),
                    nova_cc_context.InstanceConsoleContext(),
                    nova_cc_context.ConsoleSSLContext(),
                    nova_cc_context.CloudComputeContext(),
                    ch_context.InternalEndpointContext(),
                    ch_context.VolumeAPIContext('nova-common'),
                    nova_cc_context.NeutronAPIContext(),
                    nova_cc_context.SerialConsoleContext(),
                    ch_context.MemcacheContext(),
                    nova_cc_context.NovaMetadataContext()],
            }),
            (NOVA_API_PASTE, {
                'services': [s for s in resolve_services() if 'api' in s],
                'contexts': [nova_cc_context.IdentityServiceContext(),
                             nova_cc_context.APIRateLimitingContext()],
            }),
            (HAPROXY_CONF, {
                'contexts': [
                    ch_context.HAProxyContext(singlenode_mode=True),
                    nova_cc_context.HAProxyContext()],
                'services': ['haproxy'],
            }),
            (APACHE_CONF, {
                'contexts': [nova_cc_context.ApacheSSLContext(
                    determine_ports)],
                'services': ['apache2'],
            }),
            (APACHE_24_CONF, {
                'contexts': [nova_cc_context.ApacheSSLContext(
                    determine_ports)],
                'services': ['apache2'],
            }),
        ])
    return _BASE_RESOURCE_MAP


CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'

NOVA_SSH_DIR = '/etc/nova/compute_ssh/'

SERIAL_CONSOLE = {
    'packages': ['nova-serialproxy', 'nova-consoleauth',
                 'websockify'],
    'services': ['nova-serialproxy', 'nova-consoleauth'],
}


def resource_map(actual_services=True):
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.

    :param actual_services: Whether to return the actual services that run on a
        unit (ie. apache2) or the services defined in BASE_SERVICES
        (ie.nova-placement-api).
    '''
    _resource_map = copy.deepcopy(get_base_resource_map())

    if os.path.exists('/etc/apache2/conf-available'):
        _resource_map.pop(APACHE_CONF)
    else:
        _resource_map.pop(APACHE_24_CONF)

    _resource_map[NOVA_CONF]['contexts'].append(
        nova_cc_context.NeutronCCContext())

    release = ch_utils.os_release('nova-common')
    cmp_os_release = ch_utils.CompareOpenStackReleases(release)
    if cmp_os_release >= 'mitaka':
        _resource_map[NOVA_CONF]['contexts'].append(
            nova_cc_context.NovaAPISharedDBContext(relation_prefix='novaapi',
                                                   database='nova_api',
                                                   ssl_dir=NOVA_CONF_DIR)
        )

    if common.console_attributes('services'):
        _resource_map[NOVA_CONF]['services'] += (
            common.console_attributes('services'))
        # nova-consoleauth will be managed by pacemaker, if
        # single-nova-consoleauth is used, then don't monitor for the
        # nova-consoleauth service to be started (LP: #1660244).
        if (hookenv.config('single-nova-consoleauth') and
                hookenv.relation_ids('ha')):
            services = _resource_map[NOVA_CONF]['services']
            if 'nova-consoleauth' in services:
                services.remove('nova-consoleauth')

    if (hookenv.config('enable-serial-console') and cmp_os_release >= 'juno'):
        _resource_map[NOVA_CONF]['services'] += SERIAL_CONSOLE['services']

    # also manage any configs that are being updated by subordinates.
    vmware_ctxt = ch_context.SubordinateConfigContext(
        interface='nova-vmware', service='nova', config_file=NOVA_CONF)
    vmware_ctxt = vmware_ctxt()
    if vmware_ctxt and 'services' in vmware_ctxt:
        for s in vmware_ctxt['services']:
            if s not in _resource_map[NOVA_CONF]['services']:
                _resource_map[NOVA_CONF]['services'].append(s)

    if ch_utils.enable_memcache(release=release):
        _resource_map[MEMCACHED_CONF] = {
            'contexts': [ch_context.MemcacheContext()],
            'services': ['memcached']}

    if actual_services and placement_api_enabled():
        for cfile in _resource_map:
            svcs = _resource_map[cfile]['services']
            if 'nova-placement-api' in svcs:
                svcs.remove('nova-placement-api')
                if 'apache2' not in svcs:
                    svcs.append('apache2')
        wsgi_script = "/usr/bin/nova-placement-api"
        _resource_map[WSGI_NOVA_PLACEMENT_API_CONF] = {
            'contexts': [
                ch_context.WSGIWorkerConfigContext(
                    name="nova", script=wsgi_script),
                nova_cc_context.HAProxyContext()],
            'services': ['apache2']
        }
    elif not placement_api_enabled():
        for cfile in _resource_map:
            svcs = _resource_map[cfile]['services']
            if 'nova-placement-api' in svcs:
                svcs.remove('nova-placement-api')
    if enable_metadata_api():
        if actual_services:
            svcs = ['apache2']
        else:
            svcs = ['nova-api-metadata']
        _resource_map[WSGI_NOVA_METADATA_API_CONF] = {
            'contexts': [
                ch_context.WSGIWorkerConfigContext(
                    name="nova_meta",
                    user='nova',
                    group='nova',
                    script='/usr/bin/nova-metadata-wsgi'),
                nova_cc_context.MetaDataHAProxyContext()],
            'services': svcs}
    return _resource_map


def register_configs(release=None):
    release = release or ch_utils.os_release('nova-common')
    configs = ch_templating.OSConfigRenderer(
        templates_dir=TEMPLATES, openstack_release=release)
    for cfg, rscs in resource_map().items():
        configs.register(cfg, rscs['contexts'])
    return configs


def restart_map(actual_services=True):
    '''
    Constructs a restart map of config files and corresponding services

    :param actual_services: Whether to return the actual services that run on a
        unit (ie. apache2) or the services defined in BASE_SERVICES
        (ie.nova-placement-api).
    '''
    return collections.OrderedDict(
        [(cfg, v['services'])
         for cfg, v in resource_map(actual_services).items()
         if v['services']])


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


def determine_ports():
    '''Assemble a list of API ports for services we are managing'''
    ports = []
    for services in restart_map(actual_services=False).values():
        for svc in services:
            try:
                ports.append(common.api_port(svc))
            except KeyError:
                pass
    return list(set(ports))


def determine_packages():
    # currently all packages match service names
    release = ch_utils.CompareOpenStackReleases(
        ch_utils.os_release('nova-common'))
    packages = copy.deepcopy(BASE_PACKAGES)
    for v in resource_map(actual_services=False).values():
        packages.extend(v['services'])
    # The nova-api-metadata service is served via wsgi and the package is
    # only needed for the standalone service so remove it to avoid port
    # clashes.
    try:
        packages.remove("nova-api-metadata")
    except ValueError:
        pass
    if common.console_attributes('packages'):
        packages.extend(common.console_attributes('packages'))
    if (hookenv.config('enable-serial-console') and release >= 'juno'):
        packages.extend(SERIAL_CONSOLE['packages'])
    packages.extend(
        ch_utils.token_cache_pkgs(source=hookenv.config('openstack-origin')))
    if release >= 'rocky':
        packages = [p for p in packages if not p.startswith('python-')]
        packages.extend(PY3_PACKAGES)
        packages.remove('libapache2-mod-wsgi')

    return list(set(packages))


def determine_purge_packages():
    '''
    Determine list of packages that where previously installed which are no
    longer needed.

    :returns: list of package names
    '''
    release = ch_utils.CompareOpenStackReleases(
        ch_utils.os_release('keystone'))
    if release >= 'rocky':
        pkgs = [p for p in BASE_PACKAGES if p.startswith('python-')]
        pkgs.extend(['python-nova', 'python-memcache', 'libapache2-mod-wsgi'])
        return pkgs
    return []


def remove_old_packages():
    '''Purge any packages that need ot be removed.

    :returns: bool Whether packages were removed.
    '''
    installed_packages = ch_fetch.filter_missing_packages(
        determine_purge_packages())
    if installed_packages:
        ch_fetch.apt_purge(installed_packages, fatal=True)
        ch_fetch.apt_autoremove(purge=True, fatal=True)
    return bool(installed_packages)


def save_script_rc():
    env_vars = {
        'OPENSTACK_PORT_MCASTPORT': hookenv.config('ha-mcastport'),
        'OPENSTACK_SERVICE_API_EC2': 'nova-api-ec2',
        'OPENSTACK_SERVICE_API_OS_COMPUTE': 'nova-api-os-compute',
        'OPENSTACK_SERVICE_CERT': 'nova-cert',
        'OPENSTACK_SERVICE_CONDUCTOR': 'nova-conductor',
        'OPENSTACK_SERVICE_OBJECTSTORE': 'nova-objectstore',
        'OPENSTACK_SERVICE_SCHEDULER': 'nova-scheduler',
    }
    if hookenv.relation_ids('nova-volume-service'):
        env_vars['OPENSTACK_SERVICE_API_OS_VOL'] = 'nova-api-os-volume'
    ch_utils.save_script_rc(**env_vars)


def get_step_upgrade_source(new_src):
    '''
    Determine if upgrade skips a release and, if so, return source
    of skipped release.
    '''
    sources = {
        # target_src: (cur_pocket, step_src)
        # NOTE: cur_pocket == * means all upgrades to target_src must step
        #                     through step_src if step_src is higher than
        #                     current release
        'precise-icehouse': ('precise-updates/grizzly',
                             'cloud:precise-havana'),
        'precise-icehouse/proposed': ('precise-proposed/grizzly',
                                      'cloud:precise-havana/proposed'),
        'trusty-liberty': ('*', 'cloud:trusty-kilo'),
        'xenial-ocata': ('*', 'cloud:xenial-newton'),  # LP: #1711209
    }
    try:
        os_codename = ch_utils.get_os_codename_install_source(new_src)
        ubuntu_series = ch_host.lsb_release()['DISTRIB_CODENAME'].lower()
        cur_pocket, step_src = sources['%s-%s' % (ubuntu_series, os_codename)]
        current_src = ch_utils.os_release('nova-common')
        step_src_codename = ch_utils.get_os_codename_install_source(step_src)
        if cur_pocket == '*' and step_src_codename > current_src:
            return step_src
    except KeyError:
        pass

    ch_utils.configure_installation_source(new_src)

    # charmhelpers.contrib.openstack.utils.configure_installation_source()
    # configures the repository in juju_deb.list, while
    # charmhelpers.fetch.add_sources() uses cloud-archive.list, so both
    # files need to read looking for the currently configured repo.
    for fname in ['cloud-archive.list', 'juju_deb.list']:
        fpath = os.path.join('/etc/apt/sources.list.d/', fname)
        if not os.path.isfile(fpath):
            hookenv.log('Missing %s skipping it' % fpath, level=hookenv.DEBUG)
            continue

        with open(fpath, 'rt') as f:
            for line in f.readlines():
                for target_src, (cur_pocket, step_src) in sources.items():
                    if target_src != new_src:
                        continue
                    if cur_pocket in line:
                        return step_src

    return None


POLICY_RC_D = """#!/bin/bash

set -e

case $1 in
  nova-*)
    [ $2 = "start" ] && exit 101
    ;;
  *)
    ;;
esac

exit 0
"""


def enable_policy_rcd():
    with open('/usr/sbin/policy-rc.d', 'w') as policy:
        policy.write(POLICY_RC_D)
    os.chmod('/usr/sbin/policy-rc.d', 0o755)


def disable_policy_rcd():
    os.unlink('/usr/sbin/policy-rc.d')


def is_db_initialised():
    if hookenv.relation_ids('cluster'):
        dbsync_state = ch_peerstorage.peer_retrieve('dbsync_state')
        if dbsync_state == 'complete':
            hookenv.log("Database is initialised", level=hookenv.DEBUG)
            return True

    hookenv.log("Database is NOT initialised", level=hookenv.DEBUG)
    return False


def is_cellv2_init_ready():
    """Determine if we're ready to initialize the cell v2 databases

    Cells v2 init requires transport_url and database connections to be set
    in nova.conf.
    """
    amqp = ch_context.AMQPContext()
    shared_db = nova_cc_context.NovaCellV2SharedDBContext()
    if (ch_utils.CompareOpenStackReleases(
            ch_utils.os_release('nova-common')) >= 'ocata' and
            amqp() and shared_db()):
        return True

    hookenv.log(
        "OpenStack release, database, or rabbitmq not ready for Cells V2",
        level=hookenv.DEBUG)
    return False


def _do_openstack_upgrade(new_src):
    enable_policy_rcd()
    # All upgrades to Liberty are forced to step through Kilo. Liberty does
    # not have the migrate_flavor_data option (Bug #1511466) available so it
    # must be done pre-upgrade
    if (ch_utils.CompareOpenStackReleases(
            ch_utils.os_release('nova-common')) == 'kilo' and
            hookenv.is_leader()):
        migrate_nova_flavors()

    # 'nova-manage db online_data_migrations' needs to be run before moving to
    # the next release for environments upgraded using old charms where this
    # step was not being executed (LP: #1711209).
    online_data_migrations_if_needed()

    new_os_rel = ch_utils.get_os_codename_install_source(new_src)
    cmp_new_os_rel = ch_utils.CompareOpenStackReleases(new_os_rel)
    hookenv.log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    ch_utils.configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]

    ch_fetch.apt_update(fatal=True)
    ch_fetch.apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    ch_utils.reset_os_release()
    ch_fetch.apt_install(determine_packages(), fatal=True)

    remove_old_packages()

    disable_policy_rcd()

    # NOTE(jamespage) upgrade with existing config files as the
    # havana->icehouse migration enables new service_plugins which
    # create issues with db upgrades
    configs = register_configs(release=new_os_rel)
    configs.write_all()

    if cmp_new_os_rel >= 'mitaka' and not database_setup(prefix='novaapi'):
        # NOTE: Defer service restarts and database migrations for now
        #       as nova_api database is not yet created
        if (hookenv.relation_ids('cluster') and hookenv.is_leader()):
            # NOTE: reset dbsync state so that migration will complete
            #       when the nova_api database is setup.
            ch_peerstorage.peer_store('dbsync_state', None)
        return configs

    if cmp_new_os_rel >= 'ocata' and not database_setup(prefix='novacell0'):
        # NOTE: Defer service restarts and database migrations for now
        #       as nova_cell0 database is not yet created
        if (hookenv.relation_ids('cluster') and hookenv.is_leader()):
            # NOTE: reset dbsync state so that migration will complete
            #       when the novacell0 database is setup.
            ch_peerstorage.peer_store('dbsync_state', None)
        return configs

    if hookenv.is_leader():
        hookenv.status_set('maintenance', 'Running nova db migration')
        migrate_nova_databases()

    if not ch_utils.is_unit_paused_set():
        [ch_host.service_start(s) for s in services()]

    return configs


def database_setup(prefix):
    '''
    Determine when a specific database is setup
    and access is granted to the local unit.

    This function only checks the MySQL shared-db
    relation name using the provided prefix.
    '''
    key = '{}_allowed_units'.format(prefix)
    for db_rid in hookenv.relation_ids('shared-db'):
        for unit in hookenv.related_units(db_rid):
            allowed_units = hookenv.relation_get(key, rid=db_rid, unit=unit)
            if allowed_units and hookenv.local_unit() in allowed_units.split():
                return True
    return False


def do_openstack_upgrade(configs):
    new_src = hookenv.config('openstack-origin')

    step_src = get_step_upgrade_source(new_src)
    if step_src is not None:
        _do_openstack_upgrade(step_src)
    return _do_openstack_upgrade(new_src)


@ch_decorators.retry_on_exception(
    5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_nova_flavors():
    '''Runs nova-manage to migrate flavor data if needed'''
    hookenv.log('Migrating nova flavour information in database.',
                level=hookenv.INFO)
    cmd = ['nova-manage', 'db', 'migrate_flavor_data']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        hookenv.log('migrate_flavor_data failed\n{}'.format(e.output),
                    level=hookenv.ERROR)
        raise


@ch_decorators.retry_on_exception(
    5, base_delay=3, exc_type=subprocess.CalledProcessError)
def online_data_migrations_if_needed():
    '''Runs nova-manage to run online data migrations available since Mitaka'''
    if (hookenv.is_leader() and
            ch_utils.CompareOpenStackReleases(
                ch_utils.os_release('nova-common')) >= 'mitaka'):
        hookenv.log('Running online_data_migrations', level=hookenv.INFO)
        cmd = ['nova-manage', 'db', 'online_data_migrations']
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            hookenv.log('online_data_migrations failed\n{}'.format(e.output),
                        level=hookenv.ERROR)
            raise


def migrate_nova_api_database():
    '''Initialize or migrate the nova_api database'''
    if ch_utils.CompareOpenStackReleases(
            ch_utils.os_release('nova-common')) >= 'mitaka':
        hookenv.log('Migrating the nova-api database.', level=hookenv.INFO)
        cmd = ['nova-manage', 'api_db', 'sync']
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            # NOTE(coreycb): sync of api_db on upgrade from newton->ocata
            # fails but cell init is successful.
            hookenv.log('Ignoring CalledProcessError during nova-api database '
                        'migration\n{}'.format(e.output), level=hookenv.INFO)


def migrate_nova_database():
    '''Initialize or migrate the nova database'''
    hookenv.log('Migrating the nova database.', level=hookenv.INFO)
    cmd = ['nova-manage', 'db', 'sync']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        hookenv.log('db sync failed\n{}'.format(e.output), level=hookenv.ERROR)
        raise


def initialize_cell_databases():
    '''Initialize the cell0 and cell1 databases

    cell0 is stored in the database named 'nova_cell0'.
    cell1 is stored in the database named 'nova'.
    '''
    hookenv.log('Creating cell0 database records', level=hookenv.INFO)
    cmd = ['nova-manage', 'cell_v2', 'map_cell0']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        hookenv.log('map_cell0 failed\n{}'.format(e.output),
                    level=hookenv.ERROR)
        raise

    hookenv.log('Creating cell1 database records', level=hookenv.INFO)
    cmd = ['nova-manage', 'cell_v2', 'create_cell', '--name', 'cell1',
           '--verbose']
    try:
        subprocess.check_output(cmd)
        hookenv.log('cell1 was successfully created', level=hookenv.INFO)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            hookenv.log('Cell1 create_cell failed\n{}'.format(e.output),
                        level=hookenv.ERROR)
            raise
        elif e.returncode == 2:
            hookenv.log(
                'Cell1 create_cell failure ignored - a cell is already using '
                'the transport_url/database combination.', level=hookenv.INFO)


def get_cell_uuid(cell, fatal=True):
    '''Get cell uuid
    :param cell: string cell name i.e. 'cell1'
    :returns: string cell uuid
    '''
    hookenv.log("Listing cell, '{}'".format(cell), level=hookenv.INFO)
    cells = get_cell_details()
    cell_info = cells.get(cell)
    if not cell_info:
        if fatal:
            raise Exception("Cannot find cell, '{}', in list_cells."
                            "".format(cell))
        return None
    return cell_info['uuid']


def get_cell_details():
    '''Get cell details
    :returns: string cell uuid
    '''
    hookenv.log("Getting details of cells", level=hookenv.INFO)
    cells = {}
    cmd = ['sudo', 'nova-manage', 'cell_v2', 'list_cells', '--verbose']
    try:
        out = subprocess.check_output(cmd).decode('utf-8')
    except subprocess.CalledProcessError as e:
        hookenv.log('list_cells failed\n{}'.format(e.output),
                    level=hookenv.ERROR)
        raise
    for line in out.split('\n'):
        columns = line.split('|')
        if len(columns) < 2:
            continue
        columns = [c.strip() for c in columns]
        try:
            uuid.UUID(columns[2].strip())
            cells[columns[1]] = {
                'uuid': columns[2],
                'amqp': columns[3],
                'db': columns[4]}
        except ValueError:
            pass
    return cells


def update_cell_database():
    '''Update the cell1 database properties

    This should be called whenever a database or rabbitmq-server relation is
    changed to update the transport_url in the nova_api cell_mappings table.
    '''
    hookenv.log('Updating cell1 properties', level=hookenv.INFO)
    cell1_uuid = get_cell_uuid('cell1')
    cmd = ['nova-manage', 'cell_v2', 'update_cell', '--cell_uuid', cell1_uuid]
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            hookenv.log('Cell1 update_cell failed\n{}'.format(e.output),
                        level=hookenv.ERROR)
            raise
        elif e.returncode == 2:
            hookenv.log(
                'Cell1 update_cell failure ignored - the properties cannot '
                'be set.', level=hookenv.INFO)
    else:
        hookenv.log('cell1 was successfully updated', level=hookenv.INFO)


def map_instances():
    '''Map instances to cell

    Updates nova_api.instance_mappings with pre-existing instances

    :raises: Exception if Cell1 map_instances fails
    '''
    batch_size = '50000'
    cell1_uuid = get_cell_uuid('cell1')
    cmd = ['nova-manage', 'cell_v2', 'map_instances',
           '--cell_uuid', cell1_uuid, '--max-count', batch_size]
    iteration = 0
    exit_code = 1
    # Return code if 0 indicates all instances have been mapped. A return code
    # of 1 indicates this batch is complete but there are more instances that
    # still need mapping.
    while exit_code == 1:
        msg = 'Mapping instances. Batch number: {}'.format(iteration)
        hookenv.status_set('maintenance', msg)
        hookenv.log(msg, level=hookenv.INFO)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        exit_code = process.wait()
        if exit_code not in [0, 1]:
            msg = 'Cell1 map_instances failed\nstdout: {}\nstderr: {}'.format(
                stdout,
                stderr)
            hookenv.log(msg, level=hookenv.ERROR)
            raise Exception(msg)
        iteration += 1
    msg = 'Mapping instances complete'
    hookenv.status_set('maintenance', msg)
    hookenv.log(msg, level=hookenv.INFO)


def archive_deleted_rows(max_rows=None):
    hookenv.log('Archiving deleted rows', level=hookenv.INFO)
    cmd = ['nova-manage', 'db', 'archive_deleted_rows', '--verbose']
    if max_rows:
        cmd.extend(['--max_rows', str(max_rows)])
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    exit_code = process.wait()
    if exit_code not in [0, 1]:
        msg = 'Archiving deleted rows failed\nstdout: {}\nstderr: {}'.format(
            stdout,
            stderr)
        hookenv.log(msg, level=hookenv.ERROR)
        raise Exception(msg)
    else:
        return stdout


def add_hosts_to_cell():
    '''Map compute hosts to cell'''
    hookenv.log('Cell1 discover_hosts', level=hookenv.INFO)
    cell1_uuid = get_cell_uuid('cell1')
    cmd = ['nova-manage', 'cell_v2', 'discover_hosts', '--cell_uuid',
           cell1_uuid, '--verbose']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        hookenv.log('Cell1 discover_hosts failed\n{}'.format(e.output),
                    level=hookenv.ERROR)
        raise


def finalize_migrate_nova_databases():
    if hookenv.relation_ids('cluster'):
        hookenv.log('Informing peers that dbsync is complete',
                    level=hookenv.INFO)
        ch_peerstorage.peer_store('dbsync_state', 'complete')
    hookenv.log('Enabling services', level=hookenv.INFO)
    if not ch_utils.is_unit_paused_set():
        for svc in services():
            ch_host.service_resume(svc)
    else:
        hookenv.log('Unit is in paused state, not issuing start/resume to all '
                    'services')


# NOTE(jamespage): Retry deals with sync issues during one-shot HA deploys.
#                  mysql might be restarting or suchlike.
@ch_decorators.retry_on_exception(
    5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_nova_databases():
    '''Runs nova-manage to initialize new databases or migrate existing'''
    release = ch_utils.CompareOpenStackReleases(
        ch_utils.os_release('nova-common'))
    if release < 'ocata':
        migrate_nova_api_database()
        migrate_nova_database()
        online_data_migrations_if_needed()
        finalize_migrate_nova_databases()

    elif is_cellv2_init_ready():
        migrate_nova_api_database()
        initialize_cell_databases()
        migrate_nova_database()
        online_data_migrations_if_needed()
        add_hosts_to_cell()
        # Populate the cells mapping table if upgrading to a cells
        # environment for the first time eg Newton -> Ocata
        if release == 'ocata':
            map_instances()
        finalize_migrate_nova_databases()


# TODO: refactor to use unit storage or related data
def auth_token_config(setting):
    """
    Returns currently configured value for setting in api-paste.ini's
    authtoken section, or None.
    """
    _config = configparser.RawConfigParser()
    _config.read('/etc/nova/api-paste.ini')
    try:
        value = _config.get('filter:authtoken', setting)
    except:
        return None
    if value.startswith('%'):
        return None
    return value


def keystone_ca_cert_b64():
    '''Returns the local Keystone-provided CA cert if it exists, or None.'''
    if not os.path.isfile(CA_CERT_PATH):
        return None
    with open(CA_CERT_PATH, 'rb') as _in:
        return base64.b64encode(_in.read()).decode('utf-8')


def ssh_directory_for_unit(unit=None, user=None):
    if unit:
        remote_service = unit.split('/')[0]
    else:
        remote_service = hookenv.remote_unit().split('/')[0]
    if user:
        remote_service = "{}_{}".format(remote_service, user)
    _dir = os.path.join(NOVA_SSH_DIR, remote_service)
    for d in [NOVA_SSH_DIR, _dir]:
        if not os.path.isdir(d):
            os.mkdir(d)
    for f in ['authorized_keys', 'known_hosts']:
        f = os.path.join(_dir, f)
        if not os.path.isfile(f):
            open(f, 'w').close()
    return _dir


def known_hosts(unit=None, user=None):
    return os.path.join(ssh_directory_for_unit(unit, user), 'known_hosts')


def authorized_keys(unit=None, user=None):
    return os.path.join(ssh_directory_for_unit(unit, user), 'authorized_keys')


def ssh_known_host_key(host, unit=None, user=None):
    cmd = ['ssh-keygen', '-f', known_hosts(unit, user), '-H', '-F', host]
    try:
        # The first line of output is like '# Host xx found: line 1 type RSA',
        # which should be excluded.
        output = subprocess.check_output(cmd).decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return None

    if output:
        # Bug #1500589 cmd has 0 rc on precise if entry not present
        lines = output.split('\n')
        if len(lines) > 1:
            return lines[1]

    return None


def remove_known_host(host, unit=None, user=None):
    hookenv.log('Removing SSH known host entry for compute host at %s' % host)
    cmd = ['ssh-keygen', '-f', known_hosts(unit, user), '-R', host]
    subprocess.check_call(cmd)


def is_same_key(key_1, key_2):
    # The key format get will be like '|1|2rUumCavEXWVaVyB5uMl6m85pZo=|Cp'
    # 'EL6l7VTY37T/fg/ihhNb/GPgs= ssh-rsa AAAAB', we only need to compare
    # the part start with 'ssh-rsa' followed with '= ', because the hash
    # value in the beginning will change each time.
    k_1 = key_1.split('= ')[1]
    k_2 = key_2.split('= ')[1]
    return k_1 == k_2


def add_known_host(host, unit=None, user=None):
    '''Add variations of host to a known hosts file.'''
    cmd = ['ssh-keyscan', '-H', '-t', 'rsa', host]
    try:
        remote_key = subprocess.check_output(cmd).decode('utf-8').strip()
    except Exception as e:
        hookenv.log('Could not obtain SSH host key from %s' % host,
                    level=hookenv.ERROR)
        raise e

    current_key = ssh_known_host_key(host, unit, user)
    if current_key and remote_key:
        if is_same_key(remote_key, current_key):
            hookenv.log(
                'Known host key for compute host %s up to date.' % host)
            return
        else:
            remove_known_host(host, unit, user)

    hookenv.log('Adding SSH host key to known hosts for compute node at {}.'
                .format(host))
    with open(known_hosts(unit, user), 'a') as out:
        out.write(remote_key + '\n')


def ssh_authorized_key_exists(public_key, unit=None, user=None):
    with open(authorized_keys(unit, user)) as keys:
        return (' %s ' % public_key) in keys.read()


def add_authorized_key(public_key, unit=None, user=None):
    with open(authorized_keys(unit, user), 'a') as keys:
        keys.write(public_key + '\n')


def ssh_compute_add(public_key, rid=None, unit=None, user=None):
    # If remote compute node hands us a hostname, ensure we have a
    # known hosts entry for its IP, hostname and FQDN.
    private_address = hookenv.relation_get(rid=rid, unit=unit,
                                           attribute='private-address')
    hosts = []

    if not ch_ip.is_ipv6(private_address):
        hostname = hookenv.relation_get(rid=rid, unit=unit,
                                        attribute='hostname')
        if hostname:
            hosts.append(hostname.lower())

        if not ch_utils.is_ip(private_address):
            hosts.append(private_address.lower())
            hosts.append(ch_utils.get_host_ip(private_address))
            short = private_address.split('.')[0]
            if ch_ip.ns_query(short):
                hosts.append(short.lower())
        else:
            hosts.append(private_address)
            hn = ch_utils.get_hostname(private_address)
            if hn:
                hosts.append(hn.lower())
                short = hn.split('.')[0]
                if ch_ip.ns_query(short):
                    hosts.append(short.lower())
    else:
        hosts.append(private_address)

    for host in list(set(hosts)):
        add_known_host(host, unit, user)

    if not ssh_authorized_key_exists(public_key, unit, user):
        hookenv.log('Saving SSH authorized key for compute host at %s.' %
                    private_address)
        add_authorized_key(public_key, unit, user)


def ssh_known_hosts_lines(unit=None, user=None):
    known_hosts_list = []

    with open(known_hosts(unit, user)) as hosts:
        for hosts_line in hosts:
            if hosts_line.rstrip():
                known_hosts_list.append(hosts_line.rstrip())
    return(known_hosts_list)


def ssh_authorized_keys_lines(unit=None, user=None):
    authorized_keys_list = []

    with open(authorized_keys(unit, user)) as keys:
        for authkey_line in keys:
            if authkey_line.rstrip():
                authorized_keys_list.append(authkey_line.rstrip())
    return(authorized_keys_list)


def ssh_compute_remove(public_key, unit=None, user=None):
    if not (os.path.isfile(authorized_keys(unit, user)) or
            os.path.isfile(known_hosts(unit, user))):
        return

    with open(authorized_keys(unit, user), 'rt') as _keys:
        keys = [k.strip() for k in _keys.readlines()]

    if public_key not in keys:
        return

    [keys.remove(key) for key in keys if key == public_key]

    with open(authorized_keys(unit, user), 'wt') as _keys:
        keys = '\n'.join(keys)
        if not keys.endswith('\n'):
            keys += '\n'
        _keys.write(keys)


def determine_endpoints(public_url, internal_url, admin_url):
    '''Generates a dictionary containing all relevant endpoints to be
    passed to keystone as relation settings.'''
    region = hookenv.config('region')
    os_rel = ch_utils.os_release('nova-common')
    cmp_os_rel = ch_utils.CompareOpenStackReleases(os_rel)

    nova_public_url = ('%s:%s/v2/$(tenant_id)s' %
                       (public_url, common.api_port('nova-api-os-compute')))
    nova_internal_url = ('%s:%s/v2/$(tenant_id)s' %
                         (internal_url,
                          common.api_port('nova-api-os-compute')))
    nova_admin_url = ('%s:%s/v2/$(tenant_id)s' %
                      (admin_url, common.api_port('nova-api-os-compute')))
    if cmp_os_rel >= 'queens':
        nova_public_url = (
            '%s:%s/v2.1' %
            (public_url, common.api_port('nova-api-os-compute'))
        )
        nova_internal_url = (
            '%s:%s/v2.1' %
            (internal_url, common.api_port('nova-api-os-compute'))
        )
        nova_admin_url = (
            '%s:%s/v2.1' %
            (admin_url, common.api_port('nova-api-os-compute'))
        )

    ec2_public_url = '%s:%s/services/Cloud' % (
        public_url, common.api_port('nova-api-ec2'))
    ec2_internal_url = '%s:%s/services/Cloud' % (
        internal_url, common.api_port('nova-api-ec2'))
    ec2_admin_url = '%s:%s/services/Cloud' % (admin_url,
                                              common.api_port('nova-api-ec2'))

    s3_public_url = '%s:%s' % (public_url, common.api_port('nova-objectstore'))
    s3_internal_url = '%s:%s' % (internal_url,
                                 common.api_port('nova-objectstore'))
    s3_admin_url = '%s:%s' % (admin_url, common.api_port('nova-objectstore'))

    if cmp_os_rel >= 'ocata':
        placement_public_url = '%s:%s' % (
            public_url, common.api_port('nova-placement-api'))
        placement_internal_url = '%s:%s' % (
            internal_url, common.api_port('nova-placement-api'))
        placement_admin_url = '%s:%s' % (
            admin_url, common.api_port('nova-placement-api'))

    # the base endpoints
    endpoints = {
        'nova_service': 'nova',
        'nova_region': region,
        'nova_public_url': nova_public_url,
        'nova_admin_url': nova_admin_url,
        'nova_internal_url': nova_internal_url,
        'ec2_service': 'ec2',
        'ec2_region': region,
        'ec2_public_url': ec2_public_url,
        'ec2_admin_url': ec2_admin_url,
        'ec2_internal_url': ec2_internal_url,
        's3_service': 's3',
        's3_region': region,
        's3_public_url': s3_public_url,
        's3_admin_url': s3_admin_url,
        's3_internal_url': s3_internal_url,
    }

    if cmp_os_rel >= 'kilo':
        # NOTE(jamespage) drop endpoints for ec2 and s3
        #  ec2 is deprecated
        #  s3 is insecure and should die in flames
        endpoints.update({
            'ec2_service': None,
            'ec2_region': None,
            'ec2_public_url': None,
            'ec2_admin_url': None,
            'ec2_internal_url': None,
            's3_service': None,
            's3_region': None,
            's3_public_url': None,
            's3_admin_url': None,
            's3_internal_url': None,
        })

    if cmp_os_rel >= 'ocata':
        endpoints.update({
            'placement_service': 'placement',
            'placement_region': region,
            'placement_public_url': placement_public_url,
            'placement_admin_url': placement_admin_url,
            'placement_internal_url': placement_internal_url,
        })

    return endpoints


def guard_map():
    """Map of services and required interfaces that must be present before
    the service should be allowed to start

    :returns: A map of service names to interface names
    :rtype: Dict[String, String]
    """
    gmap = {}
    nova_services = resolve_services()
    if ch_utils.os_release('nova-common') not in ['essex', 'folsom']:
        nova_services.append('nova-conductor')

    nova_interfaces = ['identity-service', 'amqp']
    nova_interfaces.append('shared-db')

    for svc in nova_services:
        gmap[svc] = nova_interfaces

    return gmap


def service_guard(guard_map, contexts, active=False):
    """Inhibit services in guard_map from running unless required interfaces
    are found complete in contexts.

    `guard_map`, `contexts` and `active` are all optionally callable so that
    they don't have to run when the module is loaded.  This allows them to be
    lazy and ensure that they only need to be evaluated if the decorated
    function is actually called.

    If `active` is not "truthy" then this decorator just returns the decorated
    function with no changes.

    :param guard_map: a callable that returns a dict or a dictionary of nova
        service names <-> interface names
    :type guard_map: Option[Callable, Dict[String, String]]
    :param contexts: the map of file name -> {'services' -> [names]},
        {'contexts' -> context objects}
    :type contexts: Option[Callable, `:class:templating.OSConfigRenderer`]
    :param active: Whether this service guard is active or not, optionally
        callable
    :type active: Option[Callable, Boolean]
    :returns: wrapped function
    :rtype: Callable
    """
    def wrap(f):
        _guard_map = None
        _contexts = None
        _active = None

        def wrapped_f(*args, **kwargs):
            nonlocal _active, _contexts, _guard_map
            if _active is None:
                if callable(active):
                    _active = True if active() else False
                else:
                    _active = True if active else False
            if _active:
                if _guard_map is None:
                    if callable(guard_map):
                        _guard_map = guard_map()
                    else:
                        _guard_map = guard_map
                if _contexts is None:
                    if callable(contexts):
                        _contexts = contexts()
                    else:
                        _contexts = contexts
                incomplete_services = []
                for svc in _guard_map:
                    for interface in guard_map[svc]:
                        if interface not in _contexts.complete_contexts():
                            incomplete_services.append(svc)
                ret = f(*args, **kwargs)
                for svc in incomplete_services:
                    if ch_host.service_running(svc):
                        hookenv.log(
                            'Service {} has unfulfilled '
                            'interface requirements, stopping.'.format(svc))
                        ch_host.service_stop(svc)
                return ret
            else:
                return f(*args, **kwargs)
        return wrapped_f
    return wrap


def setup_ipv6():
    ubuntu_rel = ch_host.lsb_release()['DISTRIB_CODENAME'].lower()
    if ch_host.CompareHostReleases(ubuntu_rel) < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    if (ubuntu_rel == 'trusty' and
            ch_utils.CompareOpenStackReleases(
                ch_utils.os_release('nova-api')) < 'liberty'):
        ch_fetch.add_source(
            'deb http://archive.ubuntu.com/ubuntu trusty-backports main')
        ch_fetch.apt_update()
        ch_fetch.apt_install('haproxy/trusty-backports', fatal=True)


def get_optional_interfaces():
    """Return the optional interfaces that should be checked if the relavent
    relations have appeared.

    :returns: {general_interface: [specific_int1, specific_int2, ...], ...}
    """
    optional_interfaces = {}
    if hookenv.relation_ids('quantum-network-service'):
        optional_interfaces['quantum'] = ['quantum-network-service']
    if hookenv.relation_ids('cinder-volume-service'):
        optional_interfaces['cinder'] = ['cinder-volume-service']
    if hookenv.relation_ids('neutron-api'):
        optional_interfaces['neutron-api'] = ['neutron-api']

    return optional_interfaces


def check_optional_relations(configs):
    """Check that if we have a relation_id for high availability that we can
    get the hacluster config.  If we can't then we are blocked.

    This function is called from assess_status/set_os_workload_status as the
    charm_func and needs to return either None, None if there is no problem or
    the status, message if there is a problem.

    :param configs: an OSConfigRender() instance.
    :return 2-tuple: (string, string) = (status, message)
    """
    if hookenv.relation_ids('ha'):
        try:
            ch_cluster.get_hacluster_config()
        except:
            return ('blocked',
                    'hacluster missing configuration: '
                    'vip, vip_iface, vip_cidr')
    # return 'unknown' as the lowest priority to not clobber an existing
    # status.
    return "unknown", ""


def is_api_ready(configs):
    return (not ch_utils.incomplete_relation_data(configs,
                                                  REQUIRED_INTERFACES))


def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    # Add the cell context as its not used for rendering files, only for
    # assessing status.
    configs.register('', [nova_cc_context.NovaCellV2Context()])
    assess_status_func(configs)()
    ch_utils.os_application_version_set(VERSION_PACKAGE)


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE: REQUIRED_INTERFACES is augmented with the optional interfaces
    depending on the current config before being passed to the
    make_assess_status_func() function.

    NOTE(ajkavanagh) ports are not checked due to race hazards with services
    that don't behave sychronously w.r.t their service scripts.  e.g.
    apache2.
    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    required_interfaces = REQUIRED_INTERFACES.copy()
    required_interfaces.update(get_optional_interfaces())
    return ch_utils.make_assess_status_func(
        configs, required_interfaces,
        charm_func=check_optional_relations,
        services=services(), ports=None)


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(ch_utils.pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(ch_utils.resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=None)


def update_aws_compat_services():
    """Depending on the configuration of `disable-aws-compatibility` config
    option.

    This will stop/start and disable/enable `nova-api-ec2` and
    `nova-objectstore` services.
    """
    # if packages aren't installed, then there is nothing to do
    if ch_fetch.filter_installed_packages(AWS_COMPAT_SERVICES) != []:
        return

    if hookenv.config('disable-aws-compat'):
        # TODO: the endpoints have to removed from keystone
        for service_ in AWS_COMPAT_SERVICES:
            ch_host.service_pause(service_)
    else:
        for service_ in AWS_COMPAT_SERVICES:
            ch_host.service_resume(service_)


def serial_console_settings():
    '''Utility wrapper to retrieve serial console settings
    for use in cloud-compute relation
    '''
    return nova_cc_context.SerialConsoleContext()()


def placement_api_enabled():
    """Return true if nova-placement-api is enabled in this release"""
    return ch_utils.CompareOpenStackReleases(
        ch_utils.os_release('nova-common')) >= 'ocata'


def enable_metadata_api(release=None):
    """Should nova-metadata-api be running on this unit for this release."""
    if not release:
        release = ch_utils.os_release('nova-common')
    return ch_utils.CompareOpenStackReleases(release) >= 'rocky'


def disable_package_apache_site():
    """Ensure that the package-provided apache configuration is disabled to
    prevent it from conflicting with the charm-provided version.
    """
    if os.path.exists(PACKAGE_NOVA_PLACEMENT_API_CONF):
        subprocess.check_call(['a2dissite', 'nova-placement-api'])


def get_shared_metadatasecret():
    """Return the shared metadata secret."""
    return hookenv.leader_get(SHARED_METADATA_SECRET_KEY)


def set_shared_metadatasecret():
    """Store the shared metadata secret."""
    hookenv.leader_set({SHARED_METADATA_SECRET_KEY: uuid.uuid1()})


def get_metadata_settings(configs):
    """Return the settings for accessing the metadata service."""
    if enable_metadata_api():
        url = urlparse(
            ch_openstack_ip.canonical_url(configs, ch_openstack_ip.INTERNAL))
        settings = {
            'nova-metadata-host': url.netloc,
            'nova-metadata-protocol': url.scheme,
            'nova-metadata-port': common.api_port('nova-api-metadata'),
            'shared-metadata-secret': get_shared_metadatasecret()}
    else:
        settings = {}
    return settings


def write_vendordata(vdata):
    """Write supplied vendor data out to a file."""
    try:
        json_vdata = json.loads(vdata)
    except (TypeError, json.decoder.JSONDecodeError) as e:
        hookenv.log('Error decoding vendor-data. {}'.format(e),
                    level=hookenv.ERROR)
        return False
    with open(VENDORDATA_FILE, 'w') as vdata_file:
        vdata_file.write(json.dumps(json_vdata, sort_keys=True, indent=2))


def get_cell_db_context(db_service):
    """Return the database context for the given service name"""
    db_rid = hookenv.relation_id(
        relation_name='shared-db-cell',
        service_or_unit=db_service)
    if not db_rid:
        return {}
    return ch_context.SharedDBContext(
        relation_prefix='nova',
        ssl_dir=NOVA_CONF_DIR,
        relation_id=db_rid)()


def get_cell_amqp_context(amqp_service):
    """Return the amqp context for the given service name"""
    amq_rid = hookenv.relation_id(
        relation_name='amqp-cell',
        service_or_unit=amqp_service)
    if not amq_rid:
        return {}
    return ch_context.AMQPContext(
        ssl_dir=NOVA_CONF_DIR,
        relation_id=amq_rid)()


def get_sql_uri(db_ctxt):
    """Return the uri for conextind to the database in the supplied context"""
    uri_template = ("{database_type}://{database_user}:{database_password}"
                    "@{database_host}/{database}")
    uri = uri_template.format(**db_ctxt)
    if db_ctxt.get('database_ssl_ca'):
        uri = uri + '?ssl_ca={database_ssl_ca}'.format(**db_ctxt)
        if db_ctxt.get('database_ssl_cert'):
            uri = uri + ('&ssl_cert={database_ssl_cert}'
                         '&ssl_key={database_ssl_key}').format(**db_ctxt)
    return uri


def update_child_cell(name, db_service, amqp_service, skip_acl_check=True):
    """Register cell.

    Registering a cell requires:
        1) Complete relation with api db service.
        2) Complete relation with cells db service.
        3) Complete relation with cells amqp service.
    """
    if not is_db_initialised():
        hookenv.log(
            'Defering registering Cell {}, api db not ready.'.format(name),
            level=hookenv.DEBUG)
        return False

    existing_cells = get_cell_details()
    if not existing_cells.get('cell1'):
        hookenv.log(
            'Defering registering cell {}, api cell setup is not complete.'
            .format(name), level=hookenv.DEBUG)
        return False

    db_ctxt = get_cell_db_context(db_service)
    if not db_ctxt:
        hookenv.log(
            'Defering registering cell {}, cell db relation not ready.'
            .format(name), level=hookenv.DEBUG)
        return False
    sql_connection = get_sql_uri(db_ctxt)

    amqp_ctxt = get_cell_amqp_context(amqp_service)
    if not amqp_ctxt:
        hookenv.log(
            'Defering registering cell {}, cell amqp relation not ready.'
            .format(name), level=hookenv.DEBUG)
        return False

    cmd = [
        'nova-manage',
        'cell_v2',
    ]

    if existing_cells.get(name):
        hookenv.log(
            'Cell {} already registered, checking if details are correct.'
            .format(name), level=hookenv.DEBUG)
        if (amqp_ctxt['transport_url'] == existing_cells[name]['amqp'] and
           sql_connection == existing_cells[name]['db']):
            hookenv.log('Cell details are correct no update needed',
                        level=hookenv.DEBUG)
            return False
        else:
            hookenv.log('Cell details have changed', level=hookenv.DEBUG)
            cmd.extend([
                'update_cell',
                '--cell_uuid', existing_cells[name]['uuid']])
    else:
        hookenv.log(
            'Cell {} is new and needs to be created.'.format(name),
            level=hookenv.DEBUG)
        cmd.extend(['create_cell', '--verbose'])

    cmd.extend([
        '--name', name,
        '--transport-url', amqp_ctxt['transport_url'],
        '--database_connection', sql_connection])
    try:
        hookenv.log('Updating cell {}'.format(name), level=hookenv.DEBUG)
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        hookenv.log('Register cell failed\n{}'.format(e.output),
                    level=hookenv.ERROR)
        raise
    ch_host.service_restart('nova-scheduler')
    return True
