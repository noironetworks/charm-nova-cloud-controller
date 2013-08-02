
from charmhelpers.core.hookenv import relation_ids, relation_set
from charmhelpers.core.host import apt_install, filter_installed_packages
from charmhelpers.contrib.openstack import context, utils

#from charmhelpers.contrib.hahelpers.cluster import (
#    determine_api_port,
#    determine_haproxy_port,
#)


class ApacheSSLContext(context.ApacheSSLContext):

    interfaces = ['https']
    external_ports = []
    service_namespace = 'nova'

    def __call__(self):
        # late import to work around circular dependency
        from nova_cc_utils import determine_ports
        self.external_ports = determine_ports()
        return super(ApacheSSLContext, self).__call__()


class VolumeServiceContext(context.OSContextGenerator):
    interfaces = []

    def __call__(self):
        ctxt = {}

        os_vers = utils.get_os_codename_package('nova-common')

        if (relation_ids('nova-volume-service') and
           os_vers in ['essex', 'folsom']):
            # legacy nova-volume support, only supported in E and F
            ctxt['volume_service_config'] = 'nova.volume.api.API'
            install_pkg = filter_installed_packages(['nova-api-os-volume'])
            if install_pkg:
                apt_install(install_pkg)
        elif relation_ids('cinder-volume-service'):
            ctxt['volume_service_config'] = 'nova.volume.cinder.API'
            # kick all compute nodes to know they should use cinder now.
            [relation_set(volume_service='cinder', rid=rid)
             for rid in relation_ids('cloud-compute')]
        return ctxt


class HAProxyContext(context.OSContextGenerator):
    interfaces = ['ceph']

    def __call__(self):
        '''
        Extends the main charmhelpers HAProxyContext with a port mapping
        specific to this charm.
        Also used to extend nova.conf context with correct api_listening_ports
        '''
        # TODO
