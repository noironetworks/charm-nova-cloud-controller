# TODO: Promote all of this to charm-helpers, its shared with nova-compute

from charmhelpers.core.hookenv import (
    config,
    log,
    relation_get,
    unit_private_ip,
    ERROR,
)

from charmhelpers.contrib.openstack import context

from charmhelpers.core.host import apt_install, filter_installed_packages

from charmhelpers.contrib.openstack.utils import (
    get_os_codename_package,
    get_os_codename_install_source,
)


def _save_flag_file(path, data):
    '''
    Saves local state about plugin or manager to specified file.
    '''
    # Wonder if we can move away from this now?
    with open(path, 'wb') as out:
        out.write(data)


class QuantumPluginContext(context.OSContextGenerator):
    interfaces = []

    def _ensure_packages(self, packages):
        '''Install but do not upgrade required plugin packages'''
        required = filter_installed_packages(packages)
        if required:
            apt_install(required, fatal=True)

    def ovs_context(self):
        q_driver = 'quantum.plugins.openvswitch.ovs_quantum_plugin.'\
                   'OVSQuantumPluginV2'
        q_fw_driver = 'quantum.agent.linux.iptables_firewall.'\
                      'OVSHybridIptablesFirewallDriver'

        if get_os_codename_package('nova-common') in ['essex', 'folsom']:
            n_driver = 'nova.virt.libvirt.vif.LibvirtHybridOVSBridgeDriver'
        else:
            n_driver = 'nova.virt.libvirt.vif.LibvirtGenericVIFDriver'
        n_fw_driver = 'nova.virt.firewall.NoopFirewallDriver'

        ovs_ctxt = {
            'quantum_plugin': 'ovs',
            # quantum.conf
            'core_plugin': q_driver,
            # nova.conf
            'libvirt_vif_driver': n_driver,
            'libvirt_use_virtio_for_bridges': True,
            # ovs config
            'tenant_network_type': 'gre',
            'enable_tunneling': True,
            'tunnel_id_ranges': '1:1000',
            'local_ip': unit_private_ip(),
        }

        q_sec_groups = relation_get('quantum_security_groups')
        if q_sec_groups and q_sec_groups.lower() == 'yes':
            ovs_ctxt['quantum_security_groups'] = True
            # nova.conf
            ovs_ctxt['nova_firewall_driver'] = n_fw_driver
            # ovs conf
            ovs_ctxt['ovs_firewall_driver'] = q_fw_driver

        return ovs_ctxt

    def __call__(self):
        from nova_compute_utils import quantum_attribute

        plugin = relation_get('quantum_plugin')
        if not plugin:
            return {}

        self._ensure_packages(quantum_attribute(plugin, 'packages'))

        ctxt = {}

        if plugin == 'ovs':
            ctxt.update(self.ovs_context())

        _save_flag_file(path='/etc/nova/quantum_plugin.conf', data=plugin)

        return ctxt


# legacy
QUANTUM_PLUGINS = {
    'ovs': {
        'config': '/etc/quantum/plugins/openvswitch/ovs_quantum_plugin.ini',
        'contexts': [context.SharedDBContext(),
                     QuantumPluginContext()],
        'services': ['quantum-plugin-openvswitch-agent'],
        'packages': ['quantum-plugin-openvswitch-agent',
                     'openvswitch-datapath-dkms'],
    },
    'nvp': {
        'config': '/etc/quantum/plugins/nicira/nvp.ini',
        'services': [],
        'packages': ['quantum-plugin-nicira'],
    }
}


NEUTRON_PLUGINS = {
    'ovs': {
        'config': '/etc/neutron/plugins/openvswitch/ovs_neutron_plugin.ini',
        'contexts': [context.SharedDBContext(),
                     QuantumPluginContext()],
        'services': ['neutron-plugin-openvswitch-agent'],
        'packages': ['neutron-plugin-openvswitch-agent',
                     'openvswitch-datapath-dkms'],
    },
    'nvp': {
        'config': '/etc/neutron/plugins/nicira/nvp.ini',
        'services': [],
        'packages': ['neutron-plugin-nicira'],
    }
}


def _net_manager_enabled(manager):
    manager = config('network-manager')
    if not manager:
        return False
    return manager.lower() == manager


def network_plugin_attribute(plugin, attr):
    manager = network_manager()
    if manager == 'quantum':
        plugins = QUANTUM_PLUGINS
    else:
        plugins = NEUTRON_PLUGINS
    try:
        _plugin = plugins[plugin]
    except KeyError:
        log('Unrecognised plugin for %s: %s' % (manager, plugin), level=ERROR)
        raise
    try:
        return _plugin[attr]
    except KeyError:
        return None


def network_manager():
    '''
    Deals with the renaming of Quantum to Neutron in H and any situations
    that require compatability (eg, deploying H with network-manager=quantum,
    upgrading from G).
    '''
    release = (get_os_codename_package('nova-common', fatal=False) or
               get_os_codename_install_source() or 'essex')
    manager = config('network-manager').lower()

    if manager not in ['quantum', 'neutron']:
        return manager

    if release in ['essex']:
        # E does not support neutron
        log('Neutron networking not supported in Essex.', level=ERROR)
        raise
    elif release in ['folsom', 'grizzly']:
        # neutron is named quantum in F and G
        return 'quantum'
    else:
        # ensure accurate naming for all releases post-H
        return 'neutron'
