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

import json
import os

import base64

import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.network.ip as ch_network_ip
import charmhelpers.contrib.openstack.context as ch_context
import charmhelpers.contrib.openstack.ip as ch_ip
import charmhelpers.contrib.openstack.neutron as ch_neutron
import charmhelpers.contrib.openstack.utils as ch_utils
import charmhelpers.core.hookenv as hookenv

import hooks.nova_cc_common as common


def context_complete(ctxt):
    _missing = []
    for k, v in ctxt.items():
        if v is None or v == '':
            _missing.append(k)
    if _missing:
        hookenv.log('Missing required data: %s' % ' '.join(_missing),
                    level='INFO')
        return False
    return True


class ApacheSSLContext(ch_context.ApacheSSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'nova'

    def __init__(self, _external_ports_maybe_callable):
        self._external_ports_maybe_callable = _external_ports_maybe_callable
        self.external_ports = None
        super(ApacheSSLContext, self).__init__()

    def __call__(self):
        if self.external_ports is None:
            if callable(self._external_ports_maybe_callable):
                self.external_ports = self._external_ports_maybe_callable()
            else:
                self.external_ports = self._external_ports_maybe_callable
        return super(ApacheSSLContext, self).__call__()


class NovaCellV2Context(ch_context.OSContextGenerator):

    interfaces = ['nova-cell-api']

    def __call__(self):
        ctxt = {}
        required_keys = ['cell-name', 'amqp-service', 'db-service']
        for rid in hookenv.relation_ids('nova-cell-api'):
            for unit in hookenv.related_units(rid):
                data = hookenv.relation_get(rid=rid, unit=unit)
                if set(required_keys).issubset(data.keys()):
                    ctxt[data['cell-name']] = {
                        'amqp_service': data['amqp-service'],
                        'db_service': data['db-service']}
        return ctxt


class NovaCellV2SharedDBContext(ch_context.OSContextGenerator):
    interfaces = ['shared-db']

    def __call__(self):
        hookenv.log('Generating template context for cell v2 share-db')
        ctxt = {}
        for rid in hookenv.relation_ids('shared-db'):
            for unit in hookenv.related_units(rid):
                rdata = hookenv.relation_get(rid=rid, unit=unit)
                ctxt = {
                    'novaapi_password': rdata.get('novaapi_password'),
                    'novacell0_password': rdata.get('novacell0_password'),
                    'nova_password': rdata.get('nova_password'),
                }
                if ch_context.context_complete(ctxt):
                    return ctxt
        return {}


class CloudComputeContext(ch_context.OSContextGenerator):
    "Dummy context used by service status to check relation exists"
    interfaces = ['nova-compute']

    def __call__(self):
        ctxt = {}
        rids = [rid for rid in hookenv.relation_ids('cloud-compute')]
        if rids:
            ctxt['rids'] = rids
        return ctxt


class NeutronAPIContext(ch_context.OSContextGenerator):
    interfaces = ['neutron-api']

    def __call__(self):
        hookenv.log('Generating template context from neutron api relation')
        ctxt = {}
        for rid in hookenv.relation_ids('neutron-api'):
            for unit in hookenv.related_units(rid):
                rdata = hookenv.relation_get(rid=rid, unit=unit)
                ctxt = {
                    'neutron_url': rdata.get('neutron-url'),
                    'neutron_plugin': rdata.get('neutron-plugin'),
                    'neutron_security_groups':
                    rdata.get('neutron-security-groups'),
                    'network_manager': 'neutron',
                }
                if rdata.get('enable-sriov', '').lower() == 'true':
                    ctxt['additional_neutron_filters'] = 'PciPassthroughFilter'
                # LP Bug#1805645
                if rdata.get('dns-domain', ''):
                    ctxt['dns_domain'] = rdata.get('dns-domain')
                if context_complete(ctxt):
                    return ctxt
        return {}


class VolumeServiceContext(ch_context.OSContextGenerator):
    interfaces = ['cinder-volume-service']

    def __call__(self):
        ctxt = {}
        if hookenv.relation_ids('cinder-volume-service'):
            ctxt['volume_service'] = 'cinder'
            # kick all compute nodes to know they should use cinder now.
            for rid in hookenv.relation_ids('cloud-compute'):
                hookenv.relation_set(relation_id=rid, volume_service='cinder')
        return ctxt


class HAProxyContext(ch_context.HAProxyContext):
    interfaces = ['ceph']

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        ctxt = super(HAProxyContext, self).__call__()

        # determine which port api processes should bind to, depending
        # on existence of haproxy + apache frontends
        compute_api = ch_cluster.determine_api_port(
            common.api_port('nova-api-os-compute'), singlenode_mode=True)
        ec2_api = ch_cluster.determine_api_port(
            common.api_port('nova-api-ec2'), singlenode_mode=True)
        s3_api = ch_cluster.determine_api_port(
            common.api_port('nova-objectstore'), singlenode_mode=True)
        placement_api = ch_cluster.determine_api_port(
            common.api_port('nova-placement-api'), singlenode_mode=True)
        metadata_api = ch_cluster.determine_api_port(
            common.api_port('nova-api-metadata'), singlenode_mode=True)
        # Apache ports
        a_compute_api = ch_cluster.determine_apache_port(
            common.api_port('nova-api-os-compute'), singlenode_mode=True)
        a_ec2_api = ch_cluster.determine_apache_port(
            common.api_port('nova-api-ec2'), singlenode_mode=True)
        a_s3_api = ch_cluster.determine_apache_port(
            common.api_port('nova-objectstore'), singlenode_mode=True)
        a_placement_api = ch_cluster.determine_apache_port(
            common.api_port('nova-placement-api'), singlenode_mode=True)
        a_metadata_api = ch_cluster.determine_apache_port(
            common.api_port('nova-api-metadata'), singlenode_mode=True)
        # to be set in nova.conf accordingly.
        listen_ports = {
            'osapi_compute_listen_port': compute_api,
            'ec2_listen_port': ec2_api,
            's3_listen_port': s3_api,
            'placement_listen_port': placement_api,
            'metadata_listen_port': metadata_api,
        }

        port_mapping = {
            'nova-api-os-compute': [
                common.api_port('nova-api-os-compute'), a_compute_api],
            'nova-api-ec2': [
                common.api_port('nova-api-ec2'), a_ec2_api],
            'nova-objectstore': [
                common.api_port('nova-objectstore'), a_s3_api],
            'nova-placement-api': [
                common.api_port('nova-placement-api'), a_placement_api],
            'nova-api-metadata': [
                common.api_port('nova-api-metadata'), a_metadata_api],
        }

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        # for nova.conf
        ctxt['listen_ports'] = listen_ports
        ctxt['port'] = placement_api
        return ctxt


class MetaDataHAProxyContext(HAProxyContext):
    """Context for the nova metadata service."""

    def __call__(self):
        ctxt = super(MetaDataHAProxyContext, self).__call__()
        ctxt['port'] = ctxt['listen_ports']['metadata_listen_port']
        return ctxt


def canonical_url():
    """Returns the correct HTTP URL to this host given the state of HTTPS
    configuration and hacluster.
    """
    scheme = 'http'
    if ch_cluster.https():
        scheme = 'https'

    addr = ch_ip.resolve_address(ch_ip.INTERNAL)
    return '%s://%s' % (scheme, ch_network_ip.format_ipv6_addr(addr) or addr)


class NeutronCCContext(ch_context.NeutronContext):
    interfaces = ['quantum-network-service', 'neutron-network-service']

    @property
    def network_manager(self):
        return ch_neutron.network_manager()

    def _ensure_packages(self):
        # Only compute nodes need to ensure packages here, to install
        # required agents.
        return

    def __call__(self):
        ctxt = super(NeutronCCContext, self).__call__()
        ctxt['external_network'] = hookenv.config('neutron-external-network')
        ctxt['nova_url'] = "{}:8774/v2".format(canonical_url())
        return ctxt


class IdentityServiceContext(ch_context.IdentityServiceContext):

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
        ctxt['region'] = hookenv.config('region')

        return ctxt


class NovaConfigContext(ch_context.WorkerConfigContext):
    def __call__(self):
        ctxt = super(NovaConfigContext, self).__call__()
        ctxt['scheduler_default_filters'] = (
            hookenv.config('scheduler-default-filters'))
        if hookenv.config('pci-alias'):
            aliases = json.loads(hookenv.config('pci-alias'))
            if isinstance(aliases, list):
                ctxt['pci_aliases'] = [json.dumps(x, sort_keys=True)
                                       for x in aliases]
            else:
                ctxt['pci_alias'] = json.dumps(aliases, sort_keys=True)

        ctxt['disk_allocation_ratio'] = hookenv.config('disk-allocation-ratio')
        ctxt['cpu_allocation_ratio'] = hookenv.config('cpu-allocation-ratio')
        ctxt['ram_allocation_ratio'] = hookenv.config('ram-allocation-ratio')
        addr = ch_ip.resolve_address(ch_ip.INTERNAL)
        ctxt['host_ip'] = ch_network_ip.format_ipv6_addr(addr) or addr
        return ctxt


class NovaIPv6Context(ch_context.BindHostContext):
    def __call__(self):
        ctxt = super(NovaIPv6Context, self).__call__()
        ctxt['use_ipv6'] = hookenv.config('prefer-ipv6')
        return ctxt


class InstanceConsoleContext(ch_context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}
        servers = []
        try:
            for rid in hookenv.relation_ids('memcache'):
                for rel in hookenv.relations_for_id(rid):
                    priv_addr = rel['private-address']
                    # Format it as IPv6 address if needed
                    priv_addr = (ch_network_ip.format_ipv6_addr(priv_addr) or
                                 priv_addr)
                    servers.append("%s:%s" % (priv_addr, rel['port']))
        except Exception as ex:
            hookenv.log("Could not get memcache servers: %s" % (ex),
                        level='WARNING')
            servers = []

        ctxt['memcached_servers'] = ','.join(servers)

        # Configure nova-novncproxy https if nova-api is using https.
        if ch_cluster.https():
            cn = ch_ip.resolve_address(endpoint_type=ch_ip.INTERNAL)
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


class ConsoleSSLContext(ch_context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}

        if (hookenv.config('console-ssl-cert') and
                hookenv.config('console-ssl-key') and
                hookenv.config('console-access-protocol')):
            ssl_dir = '/etc/nova/ssl/'
            if not os.path.exists(ssl_dir):
                hookenv.log('Creating %s.' % ssl_dir, level=hookenv.DEBUG)
                os.mkdir(ssl_dir)

            cert_path = os.path.join(ssl_dir, 'nova_cert.pem')
            decode_ssl_cert = base64.b64decode(
                hookenv.config('console-ssl-cert'))

            key_path = os.path.join(ssl_dir, 'nova_key.pem')
            decode_ssl_key = base64.b64decode(
                hookenv.config('console-ssl-key'))

            with open(cert_path, 'wb') as fh:
                fh.write(decode_ssl_cert)
            with open(key_path, 'wb') as fh:
                fh.write(decode_ssl_key)

            ctxt['ssl_only'] = True
            ctxt['ssl_cert'] = cert_path
            ctxt['ssl_key'] = key_path

            if ch_cluster.is_clustered():
                ip_addr = ch_ip.resolve_address(endpoint_type=ch_ip.PUBLIC)
            else:
                ip_addr = hookenv.unit_get('private-address')

            ip_addr = ch_network_ip.format_ipv6_addr(ip_addr) or ip_addr

            _proto = hookenv.config('console-access-protocol')
            url = "https://%s:%s%s" % (
                ip_addr,
                common.console_attributes('proxy-port', proto=_proto),
                common.console_attributes('proxy-page', proto=_proto))

            if _proto == 'novnc':
                ctxt['novncproxy_base_url'] = url
            elif _proto == 'spice':
                ctxt['html5proxy_base_url'] = url

        return ctxt


class SerialConsoleContext(ch_context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ip_addr = ch_ip.resolve_address(endpoint_type=ch_ip.PUBLIC)
        ip_addr = ch_network_ip.format_ipv6_addr(ip_addr) or ip_addr

        ctxt = {
            'enable_serial_console':
                str(hookenv.config('enable-serial-console')).lower(),
            'serial_console_base_url': 'ws://{}:6083/'.format(ip_addr)
        }
        return ctxt


class APIRateLimitingContext(ch_context.OSContextGenerator):
    def __call__(self):
        ctxt = {}
        rate_rules = hookenv.config('api-rate-limit-rules')
        if rate_rules:
            ctxt['api_rate_limit_rules'] = rate_rules
        return ctxt


class NovaAPISharedDBContext(ch_context.SharedDBContext):
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


class NovaMetadataContext(ch_context.OSContextGenerator):
    '''
    Context used for configuring the nova metadata service.
    '''
    def __call__(self):
        cmp_os_release = ch_utils.CompareOpenStackReleases(
            ch_utils.os_release('nova-common'))
        ctxt = {}
        if cmp_os_release >= 'rocky':
            ctxt['vendordata_providers'] = []
            vdata = hookenv.config('vendor-data')
            vdata_url = hookenv.config('vendor-data-url')

            if vdata:
                ctxt['vendor_data'] = True
                ctxt['vendordata_providers'].append('StaticJSON')

            if vdata_url:
                ctxt['vendor_data_url'] = vdata_url
                ctxt['vendordata_providers'].append('DynamicJSON')
            ctxt['metadata_proxy_shared_secret'] = hookenv.leader_get(
                'shared-metadata-secret')
            ctxt['enable_metadata'] = True
        else:
            ctxt['enable_metadata'] = False

        return ctxt
