#!/usr/bin/python

import sys

from subprocess import check_call
from urlparse import urlparse

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_get,
    relation_ids,
    relation_set,
    open_port,
    unit_get,
)

from charmhelpers.core.host import (
    apt_install, apt_update, filter_installed_packages, restart_on_change
)

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    openstack_upgrade_available,
)

from nova_cc_utils import (
    auth_token_config,
    determine_endpoints,
    determine_packages,
    determine_ports,
    do_openstack_upgrade,
    keystone_ca_cert_b64,
    migrate_database,
    save_script_rc,
    ssh_compute_add,
    ssh_compute_remove,
    ssh_known_hosts_b64,
    ssh_authorized_keys_b64,
    register_configs,
    restart_map,
    volume_service,
    CLUSTER_RES,
)

from misc_utils import (
    network_manager,
    network_plugin,
    network_plugin_attribute,
)

from charmhelpers.contrib.hahelpers.cluster import (
    canonical_url,
    eligible_leader,
    get_hacluster_config,
    is_leader,
)

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    configure_installation_source(config('openstack-origin'))
    apt_update()
    apt_install(determine_packages(), fatal=True)
    [open_port(port) for port in determine_ports()]


@hooks.hook('config-changed')
@restart_on_change(restart_map())
def config_changed():
    if openstack_upgrade_available('nova-common'):
        do_openstack_upgrade()
    save_script_rc()
    configure_https()
    CONFIGS.write_all()


@hooks.hook('amqp-relation-joined')
@restart_on_change(restart_map())
def amqp_joined():
    relation_set(username=config('rabbit-user'), vhost=config('rabbit-vhost'))


@hooks.hook('amqp-relation-changed')
@restart_on_change(restart_map())
def amqp_changed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write('/etc/nova/nova.conf')
    if network_manager() == 'quantum':
        CONFIGS.write('/etc/quantum/quantum.conf')
    if network_manager() == 'neutron':
        CONFIGS.write('/etc/neutron/neutron.conf')


@hooks.hook('shared-db-relation-joined')
def db_joined():
    relation_set(nova_database=config('database'),
                 nova_username=config('database-user'),
                 nova_hostname=unit_get('private-address'))
    if network_manager() in ['quantum', 'neutron']:
        # XXX: Renaming relations from quantum_* to neutron_* here.
        relation_set(neutron_database=config('neutron-database'),
                     neutron_username=config('neutron-database-user'),
                     neutron_hostname=unit_get('private-address'))


@hooks.hook('shared-db-relation-changed')
@restart_on_change(restart_map())
def db_changed():
    if 'shared-db' not in CONFIGS.complete_contexts():
        log('shared-db relation incomplete. Peer not ready?')
        return
    CONFIGS.write('/etc/nova/nova.conf')

    if network_manager() in ['neutron', 'quantum']:
        plugin = network_plugin()
        # DB config might have been moved to main neutron.conf in H?
        CONFIGS.write(network_plugin_attribute(plugin, 'config'))

    if eligible_leader(CLUSTER_RES):
        migrate_database()


@hooks.hook('image-service-relation-changed')
@restart_on_change(restart_map())
def image_service_changed():
    if 'image-service' not in CONFIGS.complete_contexts():
        log('image-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write('/etc/nova/nova.conf')
    # TODO: special case config flag for essex (strip protocol)


@hooks.hook('identity-service-relation-joined')
@restart_on_change(restart_map())
def identity_joined(rid=None):
    base_url = canonical_url(CONFIGS)
    relation_set(rid=rid, **determine_endpoints(base_url))


@hooks.hook('identity-service-relation-changed')
@restart_on_change(restart_map())
def identity_changed():
    if 'identity-service' not in CONFIGS.complete_contexts():
        log('identity-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write('/etc/nova/api-paste.ini')
    if network_manager() == 'quantum':
        CONFIGS.write('/etc/quantum/api-paste.ini')
        CONFIGS.write('/etc/quantum/quantum.conf')
    if network_manager() == 'neutron':
        CONFIGS.write('/etc/neutron/neutron.conf')
    # XXX configure quantum networking


@hooks.hook('nova-volume-service-relation-joined',
            'cinder-volume-service-relation-joined')
@restart_on_change(restart_map())
def volume_joined():
    CONFIGS.write('/etc/nova/nova.conf')
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
        'service_port': auth_token_config('service_port'),
        'service_username': auth_token_config('admin_user'),
        'service_password': auth_token_config('admin_password'),
        'service_tenant_name': auth_token_config('admin_tenant_name'),
        'auth_uri': auth_token_config('auth_uri'),
    }
    return cfg


@hooks.hook('cloud-compute-relation-joined')
def compute_joined(rid=None):
    if not eligible_leader():
        return
    rel_settings = {
        'network_manager': config('network-manager'),
        'volume_service': volume_service(),
        # (comment from bash vers) XXX Should point to VIP if clustered, or
        # this may not even be needed.
        'ec2_host': unit_get('private-address'),
    }

    ks_auth_config = _auth_config()

    if network_manager() in ['quantum', 'neutron']:
        if ks_auth_config:
            rel_settings.update(ks_auth_config)
            rel_settings.update({
                # XXX: Rename these relations settings?
                'quantum_plugin': network_plugin(),
                'region': config('region'),
                'quantum_security_groups': config('quantum_security_groups'),
            })

    ks_ca = keystone_ca_cert_b64()
    if ks_auth_config and ks_ca:
        rel_settings['ca_cert'] = ks_ca
    relation_set(rid=rid, **rel_settings)


@hooks.hook('cloud-compute-relation-changed')
def compute_changed():
    migration_auth = relation_get('migration_auth_type')
    if migration_auth == 'ssh':
        key = relation_get('ssh_public_key')
        if not key:
            log('SSH migration set but peer did not publish key.')
            return
        ssh_compute_add(key, unit_get('private-address'))
        relation_set(known_hosts=ssh_known_hosts_b64(),
                     authorized_keys=ssh_authorized_keys_b64())


def compute_departed():
    ssh_compute_remove()


@hooks.hook('neutron-network-service-relation-joined',
            'quantum-network-service-relation-joined')
def quantum_joined(rid=None):
    if not eligible_leader():
        return

    if network_manager() == 'quantum':
        pkg = 'quantum-server'
    else:
        pkg = 'neutron-server'

    required_pkg = filter_installed_packages([pkg])
    if required_pkg:
        apt_install(required_pkg)

    url = canonical_url(CONFIGS) + ':9696'
    # XXX: Can we rename to neutron_*?
    rel_settings = {
        'quantum_host': urlparse(url).hostname,
        'quantum_url': url,
        'quantum_port': 9696,
        'quantum_plugin': network_plugin(),
        'region': config('region')
    }

    # inform quantum about local keystone auth config
    ks_auth_config = _auth_config()
    rel_settings.update(ks_auth_config)

    # must pass the keystone CA cert, if it exists.
    ks_ca = keystone_ca_cert_b64()
    if ks_auth_config and ks_ca:
        rel_settings['ca_cert'] = ks_ca

    relation_set(rid=rid, **rel_settings)


@hooks.hook('cluster-relation-changed',
            'cluster-relation-departed')
@restart_on_change(restart_map())
def cluster_changed():
    CONFIGS.write_all()


@hooks.hook('ha-relation-joined')
def ha_joined():
    config = get_hacluster_config()
    resources = {
        'res_nova_vip': 'ocf:heartbeat:IPaddr2',
        'res_nova_haproxy': 'lsb:haproxy',
    }
    vip_params = 'params ip="%s" cidr_netmask="%s" nic="%s"' % \
                 (config['vip'], config['vip_cidr'], config['vip_iface'])
    resource_params = {
        'res_nova_vip': vip_params,
        'res_nova_haproxy': 'op monitor interval="5s"'
    }
    init_services = {
        'res_nova_haproxy': 'haproxy'
    }
    clones = {
        'cl_nova_haproxy': 'res_nova_haproxy'
    }
    relation_set(init_services=init_services,
                 corosync_bindiface=config['ha-bindiface'],
                 corosync_mcastport=config['ha-mcastport'],
                 resources=resources,
                 resource_params=resource_params,
                 clones=clones)


@hooks.hook('ha-relation-changed')
def ha_changed():
    if not relation_get('clustered'):
        log('ha_changed: hacluster subordinate not fully clustered.')
        return
    if not is_leader(CLUSTER_RES):
        log('ha_changed: hacluster complete but we are not leader.')
        return
    log('Cluster configured, notifying other services and updating '
        'keystone endpoint configuration')
    for rid in relation_ids('identity-service'):
        identity_joined(rid=rid)


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

    for rid in relation_ids('identity-service'):
        identity_joined(rid=rid)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
