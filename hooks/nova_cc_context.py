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

from base64 import b64decode
from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    relation_set,
    log,
    DEBUG,
    related_units,
    relations_for_id,
    relation_get,
    unit_get,
)
from charmhelpers.contrib.openstack import (
    context,
    neutron,
)
from charmhelpers.contrib.hahelpers.cluster import (
    determine_apache_port,
    determine_api_port,
    https,
    is_clustered,
)
from charmhelpers.contrib.network.ip import (
    format_ipv6_addr,
)
from charmhelpers.contrib.openstack.ip import (
    resolve_address,
    INTERNAL,
    PUBLIC,
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


class NovaCellV2SharedDBContext(context.OSContextGenerator):
    interfaces = ['shared-db']

    def __call__(self):
        log('Generating template context for cell v2 share-db')
        ctxt = {}
        for rid in relation_ids('shared-db'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt = {
                    'novaapi_password': rdata.get('novaapi_password'),
                    'novacell0_password': rdata.get('novacell0_password'),
                    'nova_password': rdata.get('nova_password'),
                }
                if context.context_complete(ctxt):
                    return ctxt
        return {}


class CloudComputeContext(context.OSContextGenerator):
    "Dummy context used by service status to check relation exists"
    interfaces = ['nova-compute']

    def __call__(self):
        ctxt = {}
        rids = [rid for rid in relation_ids('cloud-compute')]
        if rids:
            ctxt['rids'] = rids
        return ctxt


class NeutronAPIContext(context.OSContextGenerator):
    interfaces = ['neutron-api']

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
                if rdata.get('enable-sriov', '').lower() == 'true':
                    ctxt['additional_neutron_filters'] = 'PciPassthroughFilter'
                if context_complete(ctxt):
                    return ctxt
        return {}


class VolumeServiceContext(context.OSContextGenerator):
    interfaces = ['cinder-volume-service']

    def __call__(self):
        ctxt = {}
        if relation_ids('cinder-volume-service'):
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
        compute_api = determine_api_port(api_port('nova-api-os-compute'),
                                         singlenode_mode=True)
        ec2_api = determine_api_port(api_port('nova-api-ec2'),
                                     singlenode_mode=True)
        s3_api = determine_api_port(api_port('nova-objectstore'),
                                    singlenode_mode=True)
        placement_api = determine_api_port(api_port('nova-placement-api'),
                                           singlenode_mode=True)
        # Apache ports
        a_compute_api = determine_apache_port(api_port('nova-api-os-compute'),
                                              singlenode_mode=True)
        a_ec2_api = determine_apache_port(api_port('nova-api-ec2'),
                                          singlenode_mode=True)
        a_s3_api = determine_apache_port(api_port('nova-objectstore'),
                                         singlenode_mode=True)
        a_placement_api = determine_apache_port(api_port('nova-placement-api'),
                                                singlenode_mode=True)
        # to be set in nova.conf accordingly.
        listen_ports = {
            'osapi_compute_listen_port': compute_api,
            'ec2_listen_port': ec2_api,
            's3_listen_port': s3_api,
            'placement_listen_port': placement_api,
        }

        port_mapping = {
            'nova-api-os-compute': [
                api_port('nova-api-os-compute'), a_compute_api],
            'nova-api-ec2': [
                api_port('nova-api-ec2'), a_ec2_api],
            'nova-objectstore': [
                api_port('nova-objectstore'), a_s3_api],
            'nova-placement-api': [
                api_port('nova-placement-api'), a_placement_api],
        }

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for nova.conf
        ctxt['listen_ports'] = listen_ports
        ctxt['port'] = placement_api
        return ctxt


def canonical_url():
    """Returns the correct HTTP URL to this host given the state of HTTPS
    configuration and hacluster.
    """
    scheme = 'http'
    if https():
        scheme = 'https'

    addr = resolve_address(INTERNAL)
    return '%s://%s' % (scheme, format_ipv6_addr(addr) or addr)


class NeutronCCContext(context.NeutronContext):
    interfaces = ['quantum-network-service', 'neutron-network-service']

    @property
    def network_manager(self):
        return neutron.network_manager()

    def _ensure_packages(self):
        # Only compute nodes need to ensure packages here, to install
        # required agents.
        return

    def __call__(self):
        ctxt = super(NeutronCCContext, self).__call__()
        ctxt['external_network'] = config('neutron-external-network')
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


class NovaConfigContext(context.WorkerConfigContext):
    def __call__(self):
        ctxt = super(NovaConfigContext, self).__call__()
        ctxt['scheduler_default_filters'] = config('scheduler-default-filters')
        if config('pci-alias'):
            ctxt['pci_alias'] = config('pci-alias')

        ctxt['disk_allocation_ratio'] = config('disk-allocation-ratio')
        ctxt['cpu_allocation_ratio'] = config('cpu-allocation-ratio')
        ctxt['ram_allocation_ratio'] = config('ram-allocation-ratio')
        addr = resolve_address(INTERNAL)
        ctxt['host_ip'] = format_ipv6_addr(addr) or addr

        if config('enable-sriov-nic-selection'):
            ctxt['enable_sriov_nic_selection'] = \
                config('enable-sriov-nic-selection')
  
        return ctxt


class NovaIPv6Context(context.BindHostContext):
    def __call__(self):
        ctxt = super(NovaIPv6Context, self).__call__()
        ctxt['use_ipv6'] = config('prefer-ipv6')
        return ctxt


class InstanceConsoleContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}
        servers = []
        try:
            for rid in relation_ids('memcache'):
                for rel in relations_for_id(rid):
                    priv_addr = rel['private-address']
                    # Format it as IPv6 address if needed
                    priv_addr = format_ipv6_addr(priv_addr) or priv_addr
                    servers.append("%s:%s" % (priv_addr, rel['port']))
        except Exception as ex:
            log("Could not get memcache servers: %s" % (ex), level='WARNING')
            servers = []

        ctxt['memcached_servers'] = ','.join(servers)

        # Configure nova-novncproxy https if nova-api is using https.
        if https():
            cn = resolve_address(endpoint_type=INTERNAL)
            if cn:
                cert_filename = 'cert_{}'.format(cn)
                key_filename = 'key_{}'.format(cn)
            else:
                cert_filename = 'cert'
                key_filename = 'key'

            ssl_dir = '/etc/apache2/ssl/nova'
            cert = os.path.join(ssl_dir, cert_filename)
            key = os.path.join(ssl_dir, key_filename)
            if os.path.exists(cert) and os.path.exists(key):
                ctxt['ssl_cert'] = cert
                ctxt['ssl_key'] = key

        return ctxt


class ConsoleSSLContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}
        from nova_cc_utils import console_attributes

        if (config('console-ssl-cert') and
            config('console-ssl-key') and
                config('console-access-protocol')):
            ssl_dir = '/etc/nova/ssl/'
            if not os.path.exists(ssl_dir):
                log('Creating %s.' % ssl_dir, level=DEBUG)
                os.mkdir(ssl_dir)

            cert_path = os.path.join(ssl_dir, 'nova_cert.pem')
            decode_ssl_cert = b64decode(config('console-ssl-cert'))

            key_path = os.path.join(ssl_dir, 'nova_key.pem')
            decode_ssl_key = b64decode(config('console-ssl-key'))

            with open(cert_path, 'w') as fh:
                fh.write(decode_ssl_cert)
            with open(key_path, 'w') as fh:
                fh.write(decode_ssl_key)

            ctxt['ssl_only'] = True
            ctxt['ssl_cert'] = cert_path
            ctxt['ssl_key'] = key_path

            if is_clustered():
                ip_addr = resolve_address(endpoint_type=PUBLIC)
            else:
                ip_addr = unit_get('private-address')

            ip_addr = format_ipv6_addr(ip_addr) or ip_addr

            _proto = config('console-access-protocol')
            url = "https://%s:%s%s" % (
                ip_addr,
                console_attributes('proxy-port', proto=_proto),
                console_attributes('proxy-page', proto=_proto))

            if _proto == 'novnc':
                ctxt['novncproxy_base_url'] = url
            elif _proto == 'spice':
                ctxt['html5proxy_base_url'] = url

        return ctxt


class SerialConsoleContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ip_addr = resolve_address(endpoint_type=PUBLIC)
        ip_addr = format_ipv6_addr(ip_addr) or ip_addr

        ctxt = {
            'enable_serial_console':
                str(config('enable-serial-console')).lower(),
            'serial_console_base_url': 'ws://{}:6083/'.format(ip_addr)
        }
        return ctxt


class APIRateLimitingContext(context.OSContextGenerator):
    def __call__(self):
        ctxt = {}
        rate_rules = config('api-rate-limit-rules')
        if rate_rules:
            ctxt['api_rate_limit_rules'] = rate_rules
        return ctxt


class NovaAPISharedDBContext(context.SharedDBContext):
    '''
    Wrapper context to support multiple database connections being
    represented to a single config file

    ctxt values are namespaced with a nova_api_ prefix
    '''
    def __call__(self):
        ctxt = super(NovaAPISharedDBContext, self).__call__()
        if ctxt is not None:
            prefix = 'nova_api_{}'
            ctxt = {prefix.format(k): v for k, v in ctxt.items()}
        return ctxt
