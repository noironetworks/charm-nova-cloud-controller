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
import subprocess
import ConfigParser

from base64 import b64encode
from collections import OrderedDict
from copy import deepcopy

from charmhelpers.contrib.openstack import context, templating

from charmhelpers.contrib.hahelpers.cluster import (
    get_hacluster_config,
)

from charmhelpers.contrib.peerstorage import (
    peer_retrieve,
    peer_store,
)

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    get_host_ip,
    get_hostname,
    get_os_codename_install_source,
    incomplete_relation_data,
    is_ip,
    os_release,
    reset_os_release,
    save_script_rc as _save_script_rc,
    is_unit_paused_set,
    make_assess_status_func,
    pause_unit,
    resume_unit,
    os_application_version_set,
    token_cache_pkgs,
    enable_memcache,
    CompareOpenStackReleases,
)

from charmhelpers.fetch import (
    apt_upgrade,
    apt_update,
    apt_install,
    add_source,
    filter_installed_packages
)

from charmhelpers.core.hookenv import (
    config,
    is_leader,
    log,
    relation_get,
    relation_ids,
    remote_unit,
    DEBUG,
    INFO,
    ERROR,
    status_set,
    related_units,
    local_unit,
)

from charmhelpers.core.host import (
    service_pause,
    service_resume,
    service_running,
    service_start,
    service_stop,
    lsb_release,
    CompareHostReleases,
)

from charmhelpers.contrib.network.ip import (
    is_ipv6,
    ns_query,
)

from charmhelpers.core.decorators import (
    retry_on_exception,
)

import nova_cc_context

TEMPLATES = 'templates/'

CLUSTER_RES = 'grp_nova_vips'

# The interface is said to be satisfied if anyone of the interfaces in the
# list has a complete context.
REQUIRED_INTERFACES = {
    'database': ['shared-db'],
    'messaging': ['amqp'],
    'identity': ['identity-service'],
    'image': ['image-service'],
    'compute': ['nova-compute'],
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
    'python-six',
    'uuid',
    'python-memcache',
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

API_PORTS = {
    'nova-api-ec2': 8773,
    'nova-api-os-compute': 8774,
    'nova-api-os-volume': 8776,
    'nova-placement-api': 8778,
    'nova-objectstore': 3333,
}

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


def resolve_services():
    _services = deepcopy(BASE_SERVICES)
    os_rel = os_release('nova-common')
    for release in SERVICE_BLACKLIST:
        if os_rel >= release or config('disable-aws-compat'):
            [_services.remove(service)
             for service in SERVICE_BLACKLIST[release]]
    return _services


BASE_RESOURCE_MAP = OrderedDict([
    (NOVA_CONF, {
        'services': resolve_services(),
        'contexts': [context.AMQPContext(ssl_dir=NOVA_CONF_DIR),
                     context.SharedDBContext(
                         relation_prefix='nova', ssl_dir=NOVA_CONF_DIR),
                     context.OSConfigFlagContext(
                         charm_flag='nova-alchemy-flags',
                         template_flag='nova_alchemy_flags'),
                     context.ImageServiceContext(),
                     context.OSConfigFlagContext(),
                     context.SubordinateConfigContext(
                         interface='nova-vmware',
                         service='nova',
                         config_file=NOVA_CONF),
                     nova_cc_context.NovaCellContext(),
                     context.SyslogContext(),
                     context.LogLevelContext(),
                     nova_cc_context.HAProxyContext(),
                     nova_cc_context.IdentityServiceContext(
                         service='nova',
                         service_user='nova'),
                     nova_cc_context.VolumeServiceContext(),
                     context.ZeroMQContext(),
                     context.NotificationDriverContext(),
                     nova_cc_context.NovaIPv6Context(),
                     nova_cc_context.NeutronCCContext(),
                     nova_cc_context.NovaConfigContext(),
                     nova_cc_context.InstanceConsoleContext(),
                     nova_cc_context.ConsoleSSLContext(),
                     nova_cc_context.CloudComputeContext(),
                     context.InternalEndpointContext(),
                     context.VolumeAPIContext('nova-common'),
                     nova_cc_context.NeutronAPIContext(),
                     nova_cc_context.SerialConsoleContext(),
                     context.MemcacheContext()],
    }),
    (NOVA_API_PASTE, {
        'services': [s for s in resolve_services() if 'api' in s],
        'contexts': [nova_cc_context.IdentityServiceContext(),
                     nova_cc_context.APIRateLimitingContext()],
    }),
    (HAPROXY_CONF, {
        'contexts': [context.HAProxyContext(singlenode_mode=True),
                     nova_cc_context.HAProxyContext()],
        'services': ['haproxy'],
    }),
    (APACHE_CONF, {
        'contexts': [nova_cc_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
    (APACHE_24_CONF, {
        'contexts': [nova_cc_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
])

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'

NOVA_SSH_DIR = '/etc/nova/compute_ssh/'

CONSOLE_CONFIG = {
    'spice': {
        'packages': ['nova-spiceproxy', 'nova-consoleauth'],
        'services': ['nova-spiceproxy', 'nova-consoleauth'],
        'proxy-page': '/spice_auto.html',
        'proxy-port': 6082,
    },
    'novnc': {
        'packages': ['nova-novncproxy', 'nova-consoleauth'],
        'services': ['nova-novncproxy', 'nova-consoleauth'],
        'proxy-page': '/vnc_auto.html',
        'proxy-port': 6080,
    },
    'xvpvnc': {
        'packages': ['nova-xvpvncproxy', 'nova-consoleauth'],
        'services': ['nova-xvpvncproxy', 'nova-consoleauth'],
        'proxy-page': '/console',
        'proxy-port': 6081,
    },
}

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
    resource_map = deepcopy(BASE_RESOURCE_MAP)

    if os.path.exists('/etc/apache2/conf-available'):
        resource_map.pop(APACHE_CONF)
    else:
        resource_map.pop(APACHE_24_CONF)

    resource_map[NOVA_CONF]['contexts'].append(
        nova_cc_context.NeutronCCContext())

    release = os_release('nova-common')
    cmp_os_release = CompareOpenStackReleases(release)
    if cmp_os_release >= 'mitaka':
        resource_map[NOVA_CONF]['contexts'].append(
            nova_cc_context.NovaAPISharedDBContext(relation_prefix='novaapi',
                                                   database='nova_api',
                                                   ssl_dir=NOVA_CONF_DIR)
        )

    if console_attributes('services'):
        resource_map[NOVA_CONF]['services'] += console_attributes('services')
        # nova-consoleauth will be managed by pacemaker, if
        # single-nova-consoleauth is used, then don't monitor for the
        # nova-consoleauth service to be started (LP: #1660244).
        if config('single-nova-consoleauth') and relation_ids('ha'):
            services = resource_map[NOVA_CONF]['services']
            if 'nova-consoleauth' in services:
                services.remove('nova-consoleauth')

    if (config('enable-serial-console') and cmp_os_release >= 'juno'):
        resource_map[NOVA_CONF]['services'] += SERIAL_CONSOLE['services']

    # also manage any configs that are being updated by subordinates.
    vmware_ctxt = context.SubordinateConfigContext(interface='nova-vmware',
                                                   service='nova',
                                                   config_file=NOVA_CONF)
    vmware_ctxt = vmware_ctxt()
    if vmware_ctxt and 'services' in vmware_ctxt:
        for s in vmware_ctxt['services']:
            if s not in resource_map[NOVA_CONF]['services']:
                resource_map[NOVA_CONF]['services'].append(s)

    if enable_memcache(release=release):
        resource_map[MEMCACHED_CONF] = {
            'contexts': [context.MemcacheContext()],
            'services': ['memcached']}

    if actual_services and placement_api_enabled():
        for cfile in resource_map:
            svcs = resource_map[cfile]['services']
            if 'nova-placement-api' in svcs:
                svcs.remove('nova-placement-api')
                if 'apache2' not in svcs:
                    svcs.append('apache2')
        wsgi_script = "/usr/bin/nova-placement-api"
        resource_map[WSGI_NOVA_PLACEMENT_API_CONF] = {
            'contexts': [context.WSGIWorkerConfigContext(name="nova",
                                                         script=wsgi_script),
                         nova_cc_context.HAProxyContext()],
            'services': ['apache2']
        }
    elif not placement_api_enabled():
        for cfile in resource_map:
            svcs = resource_map[cfile]['services']
            if 'nova-placement-api' in svcs:
                svcs.remove('nova-placement-api')

    return resource_map


def register_configs(release=None):
    release = release or os_release('nova-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def restart_map(actual_services=True):
    '''
    Constructs a restart map of config files and corresponding services

    :param actual_services: Whether to return the actual services that run on a
        unit (ie. apache2) or the services defined in BASE_SERVICES
        (ie.nova-placement-api).
    '''
    return OrderedDict(
        [(cfg, v['services'])
         for cfg, v in resource_map(actual_services).iteritems()
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
                ports.append(API_PORTS[svc])
            except KeyError:
                pass
    return list(set(ports))


def api_port(service):
    return API_PORTS[service]


def console_attributes(attr, proto=None):
    '''Leave proto unset to query attributes of the protocal specified at
    runtime'''
    if proto:
        console_proto = proto
    else:
        console_proto = config('console-access-protocol')
        if console_proto is not None and console_proto.lower() in ('none', ''):
            console_proto = None
    if attr == 'protocol':
        return console_proto
    # 'vnc' is a virtual type made up of novnc and xvpvnc
    if console_proto == 'vnc':
        if attr in ['packages', 'services']:
            return list(set(CONSOLE_CONFIG['novnc'][attr] +
                        CONSOLE_CONFIG['xvpvnc'][attr]))
        else:
            return None
    if console_proto in CONSOLE_CONFIG:
        return CONSOLE_CONFIG[console_proto][attr]
    return None


def determine_packages():
    # currently all packages match service names
    packages = deepcopy(BASE_PACKAGES)
    for v in resource_map(actual_services=False).values():
        packages.extend(v['services'])
    if console_attributes('packages'):
        packages.extend(console_attributes('packages'))
    if (config('enable-serial-console') and
            CompareOpenStackReleases(os_release('nova-common')) >= 'juno'):
        packages.extend(SERIAL_CONSOLE['packages'])

    packages.extend(token_cache_pkgs(source=config('openstack-origin')))
    return list(set(packages))


def save_script_rc():
    env_vars = {
        'OPENSTACK_PORT_MCASTPORT': config('ha-mcastport'),
        'OPENSTACK_SERVICE_API_EC2': 'nova-api-ec2',
        'OPENSTACK_SERVICE_API_OS_COMPUTE': 'nova-api-os-compute',
        'OPENSTACK_SERVICE_CERT': 'nova-cert',
        'OPENSTACK_SERVICE_CONDUCTOR': 'nova-conductor',
        'OPENSTACK_SERVICE_OBJECTSTORE': 'nova-objectstore',
        'OPENSTACK_SERVICE_SCHEDULER': 'nova-scheduler',
    }
    if relation_ids('nova-volume-service'):
        env_vars['OPENSTACK_SERVICE_API_OS_VOL'] = 'nova-api-os-volume'
    _save_script_rc(**env_vars)


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
        os_codename = get_os_codename_install_source(new_src)
        ubuntu_series = lsb_release()['DISTRIB_CODENAME'].lower()
        cur_pocket, step_src = sources['%s-%s' % (ubuntu_series, os_codename)]
        current_src = os_release('nova-common')
        step_src_codename = get_os_codename_install_source(step_src)
        if cur_pocket == '*' and step_src_codename > current_src:
            return step_src
    except KeyError:
        pass

    configure_installation_source(new_src)

    # charmhelpers.contrib.openstack.utils.configure_installation_source()
    # configures the repository in juju_deb.list, while
    # charmhelpers.fetch.add_sources() uses cloud-archive.list, so both
    # files need to read looking for the currently configured repo.
    for fname in ['cloud-archive.list', 'juju_deb.list']:
        fpath = os.path.join('/etc/apt/sources.list.d/', fname)
        if not os.path.isfile(fpath):
            log('Missing %s skipping it' % fpath, level=DEBUG)
            continue

        with open(fpath, 'r') as f:
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
    if relation_ids('cluster'):
        dbsync_state = peer_retrieve('dbsync_state')
        if dbsync_state == 'complete':
            log("Database is initialised", level=DEBUG)
            return True

    log("Database is NOT initialised", level=DEBUG)
    return False


def is_cellv2_init_ready():
    """Determine if we're ready to initialize the cell v2 databases

    Cells v2 init requires transport_url and database connections to be set
    in nova.conf.
    """
    amqp = context.AMQPContext()
    shared_db = nova_cc_context.NovaCellV2SharedDBContext()
    if (CompareOpenStackReleases(os_release('nova-common')) >= 'ocata' and
            amqp() and shared_db()):
        return True

    log("OpenStack release, database, or rabbitmq not ready for Cells V2",
        level=DEBUG)
    return False


def _do_openstack_upgrade(new_src):
    enable_policy_rcd()
    # All upgrades to Liberty are forced to step through Kilo. Liberty does
    # not have the migrate_flavor_data option (Bug #1511466) available so it
    # must be done pre-upgrade
    if (CompareOpenStackReleases(os_release('nova-common')) == 'kilo' and
            is_leader()):
        migrate_nova_flavors()

    # 'nova-manage db online_data_migrations' needs to be run before moving to
    # the next release for environments upgraded using old charms where this
    # step was not being executed (LP: #1711209).
    online_data_migrations_if_needed()

    new_os_rel = get_os_codename_install_source(new_src)
    cmp_new_os_rel = CompareOpenStackReleases(new_os_rel)
    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]

    apt_update(fatal=True)
    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    reset_os_release()
    apt_install(determine_packages(), fatal=True)

    disable_policy_rcd()

    # NOTE(jamespage) upgrade with existing config files as the
    # havana->icehouse migration enables new service_plugins which
    # create issues with db upgrades
    configs = register_configs(release=new_os_rel)
    configs.write_all()

    if cmp_new_os_rel >= 'mitaka' and not database_setup(prefix='novaapi'):
        # NOTE: Defer service restarts and database migrations for now
        #       as nova_api database is not yet created
        if (relation_ids('cluster') and is_leader()):
            # NOTE: reset dbsync state so that migration will complete
            #       when the nova_api database is setup.
            peer_store('dbsync_state', None)
        return configs

    if cmp_new_os_rel >= 'ocata' and not database_setup(prefix='novacell0'):
        # NOTE: Defer service restarts and database migrations for now
        #       as nova_cell0 database is not yet created
        if (relation_ids('cluster') and is_leader()):
            # NOTE: reset dbsync state so that migration will complete
            #       when the novacell0 database is setup.
            peer_store('dbsync_state', None)
        return configs

    if is_leader():
        status_set('maintenance', 'Running nova db migration')
        migrate_nova_databases()

    if not is_unit_paused_set():
        [service_start(s) for s in services()]

    return configs


def database_setup(prefix):
    '''
    Determine when a specific database is setup
    and access is granted to the local unit.

    This function only checks the MySQL shared-db
    relation name using the provided prefix.
    '''
    key = '{}_allowed_units'.format(prefix)
    for db_rid in relation_ids('shared-db'):
        for unit in related_units(db_rid):
            allowed_units = relation_get(key, rid=db_rid, unit=unit)
            if allowed_units and local_unit() in allowed_units.split():
                return True
    return False


def do_openstack_upgrade(configs):
    new_src = config('openstack-origin')

    step_src = get_step_upgrade_source(new_src)
    if step_src is not None:
        _do_openstack_upgrade(step_src)
    return _do_openstack_upgrade(new_src)


@retry_on_exception(5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_nova_flavors():
    '''Runs nova-manage to migrate flavor data if needed'''
    log('Migrating nova flavour information in database.', level=INFO)
    cmd = ['nova-manage', 'db', 'migrate_flavor_data']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        log('migrate_flavor_data failed\n{}'.format(e.output), level=ERROR)
        raise


@retry_on_exception(5, base_delay=3, exc_type=subprocess.CalledProcessError)
def online_data_migrations_if_needed():
    '''Runs nova-manage to run online data migrations available since Mitaka'''
    if (is_leader() and
            CompareOpenStackReleases(os_release('nova-common')) >= 'mitaka'):
        log('Running online_data_migrations', level=INFO)
        cmd = ['nova-manage', 'db', 'online_data_migrations']
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            log('online_data_migrations failed\n{}'.format(e.output),
                level=ERROR)
            raise


def migrate_nova_api_database():
    '''Initialize or migrate the nova_api database'''
    if CompareOpenStackReleases(os_release('nova-common')) >= 'mitaka':
        log('Migrating the nova-api database.', level=INFO)
        cmd = ['nova-manage', 'api_db', 'sync']
        try:
            subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            # NOTE(coreycb): sync of api_db on upgrade from newton->ocata
            # fails but cell init is successful.
            log('Ignoring CalledProcessError during nova-api database '
                'migration\n{}'.format(e.output), level=INFO)


def migrate_nova_database():
    '''Initialize or migrate the nova database'''
    log('Migrating the nova database.', level=INFO)
    cmd = ['nova-manage', 'db', 'sync']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        log('db sync failed\n{}'.format(e.output), level=ERROR)
        raise


def initialize_cell_databases():
    '''Initialize the cell0 and cell1 databases

    cell0 is stored in the database named 'nova_cell0'.
    cell1 is stored in the database named 'nova'.
    '''
    log('Creating cell0 database records', level=INFO)
    cmd = ['nova-manage', 'cell_v2', 'map_cell0']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        log('map_cell0 failed\n{}'.format(e.output), level=ERROR)
        raise

    log('Creating cell1 database records', level=INFO)
    cmd = ['nova-manage', 'cell_v2', 'create_cell', '--name', 'cell1',
           '--verbose']
    try:
        subprocess.check_output(cmd)
        log('cell1 was successfully created', level=INFO)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            log('Cell1 create_cell failed\n{}'.format(e.output), level=ERROR)
            raise
        elif e.returncode == 2:
            log('Cell1 create_cell failure ignored - a cell is already using '
                'the transport_url/database combination.', level=INFO)


def get_cell_uuid(cell):
    '''Get cell uuid
    :param cell: string cell name i.e. 'cell1'
    :returns: string cell uuid
    '''
    log("Listing cell, '{}'".format(cell), level=INFO)
    cmd = ['sudo', 'nova-manage', 'cell_v2', 'list_cells']
    try:
        out = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        log('list_cells failed\n{}'.format(e.output), level=ERROR)
        raise
    cell_uuid = out.split(cell, 1)[1].split()[1]
    if not cell_uuid:
        raise Exception("Cannot find cell, '{}', in list_cells."
                        "".format(cell))
    return cell_uuid


def update_cell_database():
    '''Update the cell1 database properties

    This should be called whenever a database or rabbitmq-server relation is
    changed to update the transport_url in the nova_api cell_mappings table.
    '''
    log('Updating cell1 properties', level=INFO)
    cell1_uuid = get_cell_uuid('cell1')
    cmd = ['nova-manage', 'cell_v2', 'update_cell', '--cell_uuid', cell1_uuid]
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            log('Cell1 update_cell failed\n{}'.format(e.output), level=ERROR)
            raise
        elif e.returncode == 2:
            log('Cell1 update_cell failure ignored - the properties cannot '
                'be set.', level=INFO)
    else:
        log('cell1 was successfully updated', level=INFO)


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
        status_set('maintenance', msg)
        log(msg, level=INFO)
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        stdout, stderr = process.communicate()
        exit_code = process.wait()
        if exit_code not in [0, 1]:
            msg = 'Cell1 map_instances failed\nstdout: {}\nstderr: {}'.format(
                stdout,
                stderr)
            log(msg, level=ERROR)
            raise Exception(msg)
        iteration += 1
    msg = 'Mapping instances complete'
    status_set('maintenance', msg)
    log(msg, level=INFO)


def archive_deleted_rows(max_rows=None):
    log('Archiving deleted rows', level=INFO)
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
        log(msg, level=ERROR)
        raise Exception(msg)
    else:
        return stdout


def add_hosts_to_cell():
    '''Map compute hosts to cell'''
    log('Cell1 discover_hosts', level=INFO)
    cell1_uuid = get_cell_uuid('cell1')
    cmd = ['nova-manage', 'cell_v2', 'discover_hosts', '--cell_uuid',
           cell1_uuid, '--verbose']
    try:
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        log('Cell1 discover_hosts failed\n{}'.format(e.output), level=ERROR)
        raise


def finalize_migrate_nova_databases():
    if relation_ids('cluster'):
        log('Informing peers that dbsync is complete', level=INFO)
        peer_store('dbsync_state', 'complete')
    log('Enabling services', level=INFO)
    if not is_unit_paused_set():
        for svc in services():
            service_resume(svc)
    else:
        log('Unit is in paused state, not issuing start/resume to all '
            'services')


# NOTE(jamespage): Retry deals with sync issues during one-shot HA deploys.
#                  mysql might be restarting or suchlike.
@retry_on_exception(5, base_delay=3, exc_type=subprocess.CalledProcessError)
def migrate_nova_databases():
    '''Runs nova-manage to initialize new databases or migrate existing'''
    release = CompareOpenStackReleases(os_release('nova-common'))
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
    config = ConfigParser.RawConfigParser()
    config.read('/etc/nova/api-paste.ini')
    try:
        value = config.get('filter:authtoken', setting)
    except:
        return None
    if value.startswith('%'):
        return None
    return value


def keystone_ca_cert_b64():
    '''Returns the local Keystone-provided CA cert if it exists, or None.'''
    if not os.path.isfile(CA_CERT_PATH):
        return None
    with open(CA_CERT_PATH) as _in:
        return b64encode(_in.read())


def ssh_directory_for_unit(unit=None, user=None):
    if unit:
        remote_service = unit.split('/')[0]
    else:
        remote_service = remote_unit().split('/')[0]
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
        output = subprocess.check_output(cmd).strip()
    except subprocess.CalledProcessError:
        return None

    if output:
        # Bug #1500589 cmd has 0 rc on precise if entry not present
        lines = output.split('\n')
        if len(lines) > 1:
            return lines[1]

    return None


def remove_known_host(host, unit=None, user=None):
    log('Removing SSH known host entry for compute host at %s' % host)
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
        remote_key = subprocess.check_output(cmd).strip()
    except Exception as e:
        log('Could not obtain SSH host key from %s' % host, level=ERROR)
        raise e

    current_key = ssh_known_host_key(host, unit, user)
    if current_key and remote_key:
        if is_same_key(remote_key, current_key):
            log('Known host key for compute host %s up to date.' % host)
            return
        else:
            remove_known_host(host, unit, user)

    log('Adding SSH host key to known hosts for compute node at %s.' % host)
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
    private_address = relation_get(rid=rid, unit=unit,
                                   attribute='private-address')
    hosts = [private_address]

    if not is_ipv6(private_address):
        if relation_get('hostname'):
            hosts.append(relation_get('hostname'))

        if not is_ip(private_address):
            hosts.append(get_host_ip(private_address))
            short = private_address.split('.')[0]
            if ns_query(short):
                hosts.append(short)
        else:
            hn = get_hostname(private_address)
            if hn:
                hosts.append(hn)
                short = hn.split('.')[0]
                if ns_query(short):
                    hosts.append(short)

    for host in list(set(hosts)):
        add_known_host(host, unit, user)

    if not ssh_authorized_key_exists(public_key, unit, user):
        log('Saving SSH authorized key for compute host at %s.' %
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

    with open(authorized_keys(unit, user)) as _keys:
        keys = [k.strip() for k in _keys.readlines()]

    if public_key not in keys:
        return

    [keys.remove(key) for key in keys if key == public_key]

    with open(authorized_keys(unit, user), 'w') as _keys:
        keys = '\n'.join(keys)
        if not keys.endswith('\n'):
            keys += '\n'
        _keys.write(keys)


def determine_endpoints(public_url, internal_url, admin_url):
    '''Generates a dictionary containing all relevant endpoints to be
    passed to keystone as relation settings.'''
    region = config('region')
    os_rel = os_release('nova-common')
    cmp_os_rel = CompareOpenStackReleases(os_rel)

    nova_public_url = ('%s:%s/v2/$(tenant_id)s' %
                       (public_url, api_port('nova-api-os-compute')))
    nova_internal_url = ('%s:%s/v2/$(tenant_id)s' %
                         (internal_url, api_port('nova-api-os-compute')))
    nova_admin_url = ('%s:%s/v2/$(tenant_id)s' %
                      (admin_url, api_port('nova-api-os-compute')))
    ec2_public_url = '%s:%s/services/Cloud' % (
        public_url, api_port('nova-api-ec2'))
    ec2_internal_url = '%s:%s/services/Cloud' % (
        internal_url, api_port('nova-api-ec2'))
    ec2_admin_url = '%s:%s/services/Cloud' % (admin_url,
                                              api_port('nova-api-ec2'))

    s3_public_url = '%s:%s' % (public_url, api_port('nova-objectstore'))
    s3_internal_url = '%s:%s' % (internal_url, api_port('nova-objectstore'))
    s3_admin_url = '%s:%s' % (admin_url, api_port('nova-objectstore'))

    if cmp_os_rel >= 'ocata':
        placement_public_url = '%s:%s' % (
            public_url, api_port('nova-placement-api'))
        placement_internal_url = '%s:%s' % (
            internal_url, api_port('nova-placement-api'))
        placement_admin_url = '%s:%s' % (
            admin_url, api_port('nova-placement-api'))

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
    '''Map of services and required interfaces that must be present before
    the service should be allowed to start'''
    gmap = {}
    nova_services = resolve_services()
    if os_release('nova-common') not in ['essex', 'folsom']:
        nova_services.append('nova-conductor')

    nova_interfaces = ['identity-service', 'amqp']
    nova_interfaces.append('shared-db')

    for svc in nova_services:
        gmap[svc] = nova_interfaces

    return gmap


def service_guard(guard_map, contexts, active=False):
    '''Inhibit services in guard_map from running unless
    required interfaces are found complete in contexts.'''
    def wrap(f):
        def wrapped_f(*args):
            if active is True:
                incomplete_services = []
                for svc in guard_map:
                    for interface in guard_map[svc]:
                        if interface not in contexts.complete_contexts():
                            incomplete_services.append(svc)
                f(*args)
                for svc in incomplete_services:
                    if service_running(svc):
                        log('Service {} has unfulfilled '
                            'interface requirements, stopping.'.format(svc))
                        service_stop(svc)
            else:
                f(*args)
        return wrapped_f
    return wrap


def setup_ipv6():
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(ubuntu_rel) < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    if (ubuntu_rel == 'trusty' and
            CompareOpenStackReleases(os_release('nova-api')) < 'liberty'):
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports '
                   'main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


def get_optional_interfaces():
    """Return the optional interfaces that should be checked if the relavent
    relations have appeared.

    :returns: {general_interface: [specific_int1, specific_int2, ...], ...}
    """
    optional_interfaces = {}
    if relation_ids('quantum-network-service'):
        optional_interfaces['quantum'] = ['quantum-network-service']
    if relation_ids('cinder-volume-service'):
        optional_interfaces['cinder'] = ['cinder-volume-service']
    if relation_ids('neutron-api'):
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
    if relation_ids('ha'):
        try:
            get_hacluster_config()
        except:
            return ('blocked',
                    'hacluster missing configuration: '
                    'vip, vip_iface, vip_cidr')
    # return 'unknown' as the lowest priority to not clobber an existing
    # status.
    return "unknown", ""


def is_api_ready(configs):
    return (not incomplete_relation_data(configs, REQUIRED_INTERFACES))


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
    assess_status_func(configs)()
    os_application_version_set(VERSION_PACKAGE)


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
    return make_assess_status_func(
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
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


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
    if filter_installed_packages(AWS_COMPAT_SERVICES) != []:
        return

    if config('disable-aws-compat'):
        # TODO: the endpoints have to removed from keystone
        for service_ in AWS_COMPAT_SERVICES:
            service_pause(service_)
    else:
        for service_ in AWS_COMPAT_SERVICES:
            service_resume(service_)


def serial_console_settings():
    '''Utility wrapper to retrieve serial console settings
    for use in cloud-compute relation
    '''
    return nova_cc_context.SerialConsoleContext()()


def placement_api_enabled():
    """Return true if nova-placement-api is enabled in this release"""
    return CompareOpenStackReleases(os_release('nova-common')) >= 'ocata'


def disable_package_apache_site():
    """Ensure that the package-provided apache configuration is disabled to
    prevent it from conflicting with the charm-provided version.
    """
    if os.path.exists(PACKAGE_NOVA_PLACEMENT_API_CONF):
        subprocess.check_call(['a2dissite', 'nova-placement-api'])
