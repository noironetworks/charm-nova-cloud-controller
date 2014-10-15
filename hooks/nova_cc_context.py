from charmhelpers.core.hookenv import (
    config, relation_ids, relation_set, log, ERROR,
    unit_get, related_units, relation_get)

from charmhelpers.fetch import apt_install, filter_installed_packages
from charmhelpers.contrib.openstack import context, neutron, utils

from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port,
    https,
    is_clustered
)

from charmhelpers.contrib.network.ip import (
    get_ipv6_addr
)


def context_complete(ctxt):
    _missing = []
    for k, v in ctxt.iteritems():
        if v is None or v == '':
            _missing.append(k)
    if _missing:
        log('Missing required data: %s' % ' '.join(_missing), level='INFO')
        return False
    return True


class ApacheSSLContext(context.ApacheSSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'nova'

    def __call__(self):
        # late import to work around circular dependency
        from nova_cc_utils import determine_ports
        self.external_ports = determine_ports()
        return super(ApacheSSLContext, self).__call__()


class NovaCellContext(context.OSContextGenerator):
    interfaces = ['nova-cell']

    def __call__(self):
        log('Generating template context for cell')
        ctxt = {}
        for rid in relation_ids('cell'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt = {
                    'cell_type': rdata.get('cell_type'),
                    'cell_name': rdata.get('cell_name'),
                }
                if context.context_complete(ctxt):
                    return ctxt
        return {}


class NeutronAPIContext(context.OSContextGenerator):

    def __call__(self):
        log('Generating template context from neutron api relation')
        ctxt = {}
        for rid in relation_ids('neutron-api'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt = {
                    'neutron_url': rdata.get('neutron-url'),
                    'neutron_plugin': rdata.get('neutron-plugin'),
                    'neutron_security_groups':
                    rdata.get('neutron-security-groups'),
                    'network_manager': 'neutron',
                }
                if context_complete(ctxt):
                    return ctxt
        return {}


class VolumeServiceContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}

        if relation_ids('nova-volume-service'):
            if utils.os_release('nova-common') not in ['essex', 'folsom']:
                e = ('Attempting to relate a nova-volume service to an '
                     'Nova version (%s).  Use cinder.')
                log(e, level=ERROR)

                raise context.OSContextError(e)
            install_pkg = filter_installed_packages(['nova-api-os-volume'])
            if install_pkg:
                apt_install(install_pkg)
            ctxt['volume_service'] = 'nova-volume'
        elif relation_ids('cinder-volume-service'):
            ctxt['volume_service'] = 'cinder'
            # kick all compute nodes to know they should use cinder now.
            [relation_set(relation_id=rid, volume_service='cinder')
             for rid in relation_ids('cloud-compute')]
        return ctxt


class HAProxyContext(context.HAProxyContext):
    interfaces = ['ceph']

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        from nova_cc_utils import api_port
        ctxt = super(HAProxyContext, self).__call__()

        # determine which port api processes should bind to, depending
        # on existence of haproxy + apache frontends
        compute_api = determine_api_port(api_port('nova-api-os-compute'))
        ec2_api = determine_api_port(api_port('nova-api-ec2'))
        s3_api = determine_api_port(api_port('nova-objectstore'))
        nvol_api = determine_api_port(api_port('nova-api-os-volume'))
        neutron_api = determine_api_port(api_port('neutron-server'))

        # Apache ports
        a_compute_api = determine_apache_port(api_port('nova-api-os-compute'))
        a_ec2_api = determine_apache_port(api_port('nova-api-ec2'))
        a_s3_api = determine_apache_port(api_port('nova-objectstore'))
        a_nvol_api = determine_apache_port(api_port('nova-api-os-volume'))
        a_neutron_api = determine_apache_port(api_port('neutron-server'))

        # to be set in nova.conf accordingly.
        listen_ports = {
            'osapi_compute_listen_port': compute_api,
            'ec2_listen_port': ec2_api,
            's3_listen_port': s3_api,
        }

        port_mapping = {
            'nova-api-os-compute': [
                api_port('nova-api-os-compute'), a_compute_api],
            'nova-api-ec2': [
                api_port('nova-api-ec2'), a_ec2_api],
            'nova-objectstore': [
                api_port('nova-objectstore'), a_s3_api],
        }

        if relation_ids('nova-volume-service'):
            port_mapping.update({
                'nova-api-ec2': [
                    api_port('nova-api-ec2'), a_nvol_api],
            })
            listen_ports['osapi_volume_listen_port'] = nvol_api

        if neutron.network_manager() in ['neutron', 'quantum']:
            port_mapping.update({
                'neutron-server': [
                    api_port('neutron-server'), a_neutron_api]
            })
            # quantum/neutron.conf listening port, set separte from nova's.
            ctxt['neutron_bind_port'] = neutron_api

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for nova.conf
        ctxt['listen_ports'] = listen_ports
        return ctxt


def canonical_url(vip_setting='vip'):
    '''
    Returns the correct HTTP URL to this host given the state of HTTPS
    configuration and hacluster.

    :vip_setting:                str: Setting in charm config that specifies
                                      VIP address.
    '''
    scheme = 'http'
    if https():
        scheme = 'https'

    if config('prefer-ipv6'):
        if is_clustered():
            addr = '[%s]' % config(vip_setting)
        else:
            addr = '[%s]' % get_ipv6_addr(exc_list=[config('vip')])[0]
    else:
        if is_clustered():
            addr = config(vip_setting)
        else:
            addr = unit_get('private-address')

    return '%s://%s' % (scheme, addr)


class NeutronCCContext(context.NeutronContext):
    interfaces = []

    @property
    def plugin(self):
        from nova_cc_utils import neutron_plugin
        return neutron_plugin()

    @property
    def network_manager(self):
        return neutron.network_manager()

    @property
    def neutron_security_groups(self):
        sec_groups = (config('neutron-security-groups') or
                      config('quantum-security-groups'))
        return sec_groups.lower() == 'yes'

    def _ensure_packages(self):
        # Only compute nodes need to ensure packages here, to install
        # required agents.
        return

    def __call__(self):
        ctxt = super(NeutronCCContext, self).__call__()
        ctxt['external_network'] = config('neutron-external-network')
        if config('quantum-plugin') in ['nvp', 'nsx']:
            _config = config()
            for k, v in _config.iteritems():
                if k.startswith('nvp'):
                    ctxt[k.replace('-', '_')] = v
            if 'nvp-controllers' in _config:
                ctxt['nvp_controllers'] = \
                    ','.join(_config['nvp-controllers'].split())
                ctxt['nvp_controllers_list'] = \
                    _config['nvp-controllers'].split()
        ctxt['nova_url'] = "{}:8774/v2".format(canonical_url())

        return ctxt


class IdentityServiceContext(context.IdentityServiceContext):

    def __call__(self):
        ctxt = super(IdentityServiceContext, self).__call__()
        if not ctxt:
            return

        # the ec2 api needs to know the location of the keystone ec2
        # tokens endpoint, set in nova.conf
        ec2_tokens = '%s://%s:%s/v2.0/ec2tokens' % (
            ctxt['service_protocol'] or 'http',
            ctxt['service_host'],
            ctxt['service_port']
        )
        ctxt['keystone_ec2_url'] = ec2_tokens
        ctxt['region'] = config('region')

        return ctxt


class NovaPostgresqlDBContext(context.PostgresqlDBContext):
    interfaces = ['pgsql-nova-db']


class NeutronPostgresqlDBContext(context.PostgresqlDBContext):
    interfaces = ['pgsql-neutron-db']

    def __init__(self):
        super(NeutronPostgresqlDBContext,
              self).__init__(config('neutron-database'))


class NovaConfigContext(context.WorkerConfigContext):
    def __call__(self):
        ctxt = super(NovaConfigContext, self).__call__()
        ctxt['cpu_allocation_ratio'] = config('cpu-allocation-ratio')
        ctxt['ram_allocation_ratio'] = config('ram-allocation-ratio')
        return ctxt


class NovaIPv6Context(context.BindHostContext):
    def __call__(self):
        ctxt = super(NovaIPv6Context, self).__call__()
        ctxt['use_ipv6'] = config('prefer-ipv6')
        return ctxt
