import os
import subprocess
import ConfigParser

from base64 import b64encode
from collections import OrderedDict
from copy import deepcopy

from charmhelpers.contrib.openstack import templating, context

from charmhelpers.contrib.openstack.utils import (
    get_os_codename_package,
    save_script_rc as _save_script_rc,
)

from charmhelpers.core.hookenv import (
    config,
    relation_ids,
)

import nova_cc_context

TEMPLATES = 'templates/'

CLUSTER_RES = 'res_nova_vip'

# removed from original: python-mysqldb python-keystone charm-helper-sh
BASE_PACKAGES = [
    'apache2',
    'haproxy',
    'uuid',
]

BASE_SERVICES = [
    'nova-api-ec2',
    'nova-api-os-compute',
    'nova-objectstore',
    'nova-cert',
    'nova-scheduler',
]

API_PORTS = {
    'nova-api-ec2': 8773,
    'nova-api-os-compute': 8774,
    'nova-api-os-volume': 8776,
    'nova-objectstore': 3333,
    'quantum-server': 9696,
}

BASE_RESOURCE_MAP = OrderedDict([
    ('/etc/nova/nova.conf', {
        'services': BASE_SERVICES,
        'contexts': [context.AMQPContext(),
                     context.SharedDBContext(),
                     context.ImageServiceContext(),
                     nova_cc_context.VolumeServiceContext()],
    }),
    ('/etc/nova/api-paste.ini', {
        'services': [s for s in BASE_SERVICES if 'api' in s],
        'contexts': [context.IdentityServiceContext()],
    }),
    ('/etc/quantum/quantum.conf', {
        'services': ['quantum-server'],
        'contexts': [],
    }),
    ('/etc/quantum/api-paste.ini', {
        'services': ['quantum-server'],
        'contexts': [],
    }),
    ('/etc/haproxy/haproxy.cfg', {
        'contexts': [context.HAProxyContext(),
                     nova_cc_context.HAProxyContext()],
        'services': ['haproxy'],
    }),
    ('/etc/apache2/sites-available/openstack_https_frontend', {
        'contexts': [],
        'contexts': [nova_cc_context.ApacheSSLContext()],
        'services': ['apache2'],
    }),
])

CA_CERT_PATH = '/usr/local/share/ca-certificates/keystone_juju_ca_cert.crt'


def resource_map():
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    resource_map = deepcopy(BASE_RESOURCE_MAP)

    if relation_ids('nova-volume-service'):
        # if we have a relation to a nova-volume service, we're
        # also managing the nova-volume API endpoint (legacy)
        resource_map['/etc/nova/nova.conf']['services'].append(
            'nova-api-os-volume')

    if config('network-manager').lower() != 'quantum':
        # pop out quantum resources if not deploying it. easier to
        # remove it from the base ordered dict than add it in later
        # and still preserve ordering for restart_map().
        [resource_map.pop(k) for k in list(resource_map.iterkeys())
         if 'quantum' in k]
    return resource_map


def register_configs():
    release = get_os_codename_package('nova-common', fatal=False) or 'essex'
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map.iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def restart_map():
    return {k: v['services'] for k, v in resource_map().iteritems()}


def determine_ports():
    '''Assemble a list of API ports for services we are managing'''
    ports = []
    for cfg, services in restart_map().iteritems():
        for service in services:
            try:
                ports.append(API_PORTS[service])
            except KeyError:
                pass
    return ports


def determine_packages():
    # currently all packages match service names
    packages = [] + BASE_PACKAGES
    for k, v in resource_map().iteritems():
        packages.extend(v['services'])
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
    if config('network-manager').lower() == 'quantum':
        env_vars['OPENSTACK_SERVICE_API_QUANTUM'] = 'quantum-server'
    _save_script_rc(**env_vars)


def do_openstack_upgrade():
    # TODO
    pass


def quantum_plugin():
    return config('quantum-plugin').lower()


def volume_service():
    '''Specifies correct volume API for specific OS release'''
    os_vers = get_os_codename_package('nova-common')
    if os_vers == 'essex':
        return 'nova-volume'
    elif os_vers == 'folsom':  # support both drivers in folsom.
        if not relation_ids('cinder-volume-service'):
            return 'nova-volume'
    return 'cinder'


def migrate_database():
    '''Runs nova-manage to initialize a new database or migrate existing'''
    cmd = ['nova-manage', 'db', 'sync']
    subprocess.check_call(cmd)


def auth_token_config(setting):
    '''
    Returns currently configured value for setting in api-paste.ini's
    authtoken section, or None.
    '''
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


def ssh_compute_add():
    pass


def determine_endpoints():
    pass
