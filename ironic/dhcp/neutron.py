#
# Copyright 2014 OpenStack Foundation
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import time

from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client as clientv20
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import netutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LW
from ironic.common import keystone
from ironic.common import network
from ironic.dhcp import base
from ironic.drivers.modules import ssh


neutron_opts = [
    cfg.StrOpt('url',
               default='http://$my_ip:9696',
               help='URL for connecting to neutron.'),
    cfg.IntOpt('url_timeout',
               default=30,
               help='Timeout value for connecting to neutron in seconds.'),
    cfg.IntOpt('retries',
               default=3,
               help='Client retries in the case of a failed request.'),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               help='Default authentication strategy to use when connecting '
                    'to neutron. Can be either "keystone" or "noauth". '
                    'Running neutron in noauth mode (related to but not '
                    'affected by this setting) is insecure and should only be '
                    'used for testing.'),
    cfg.StrOpt('cleaning_network_uuid',
               help='UUID of the network to create Neutron ports on when '
                    'booting to a ramdisk for cleaning/zapping using Neutron '
                    'DHCP')
]

CONF = cfg.CONF
CONF.import_opt('my_ip', 'ironic.netconf')
CONF.register_opts(neutron_opts, group='neutron')
LOG = logging.getLogger(__name__)


def _build_client(token=None):
    """Utility function to create Neutron client."""
    params = {
        'timeout': CONF.neutron.url_timeout,
        'retries': CONF.neutron.retries,
        'insecure': CONF.keystone_authtoken.insecure,
        'ca_cert': CONF.keystone_authtoken.certfile,
    }

    if CONF.neutron.auth_strategy not in ['noauth', 'keystone']:
        raise exception.ConfigInvalid(_('Neutron auth_strategy should be '
                                        'either "noauth" or "keystone".'))

    if CONF.neutron.auth_strategy == 'noauth':
        params['endpoint_url'] = CONF.neutron.url
        params['auth_strategy'] = 'noauth'
    elif (CONF.neutron.auth_strategy == 'keystone' and
          token is None):
        params['endpoint_url'] = (CONF.neutron.url or
                                  keystone.get_service_url('neutron'))
        params['username'] = CONF.keystone_authtoken.admin_user
        params['tenant_name'] = CONF.keystone_authtoken.admin_tenant_name
        params['password'] = CONF.keystone_authtoken.admin_password
        params['auth_url'] = (CONF.keystone_authtoken.auth_uri or '')
        if CONF.keystone.region_name:
            params['region_name'] = CONF.keystone.region_name
    else:
        params['token'] = token
        params['endpoint_url'] = CONF.neutron.url
        params['auth_strategy'] = None

    return clientv20.Client(**params)


class NeutronDHCPApi(base.BaseDHCP):
    """API for communicating to neutron 2.x API."""

    def update_port_dhcp_opts(self, port_id, dhcp_options, token=None):
        """Update a port's attributes.

        Update one or more DHCP options on the specified port.
        For the relevant API spec, see
        http://docs.openstack.org/api/openstack-network/2.0/content/extra-dhc-opt-ext-update.html

        :param port_id: designate which port these attributes
                        will be applied to.
        :param dhcp_options: this will be a list of dicts, e.g.

                             ::

                              [{'opt_name': 'bootfile-name',
                                'opt_value': 'pxelinux.0'},
                               {'opt_name': 'server-ip-address',
                                'opt_value': '123.123.123.456'},
                               {'opt_name': 'tftp-server',
                                'opt_value': '123.123.123.123'}]
        :param token: optional auth token.

        :raises: FailedToUpdateDHCPOptOnPort
        """
        port_req_body = {'port': {'extra_dhcp_opts': dhcp_options}}
        try:
            _build_client(token).update_port(port_id, port_req_body)
        except neutron_client_exc.NeutronClientException:
            LOG.exception(_LE("Failed to update Neutron port %s."), port_id)
            raise exception.FailedToUpdateDHCPOptOnPort(port_id=port_id)

    def update_port_address(self, port_id, address, token=None):
        """Update a port's mac address.

        :param port_id: Neutron port id.
        :param address: new MAC address.
        :param token: optional auth token.
        :raises: FailedToUpdateMacOnPort
        """
        port_req_body = {'port': {'mac_address': address}}
        try:
            _build_client(token).update_port(port_id, port_req_body)
        except neutron_client_exc.NeutronClientException:
            LOG.exception(_LE("Failed to update MAC address on Neutron "
                              "port %s."), port_id)
            raise exception.FailedToUpdateMacOnPort(port_id=port_id)

    def update_dhcp_opts(self, task, options, vifs=None):
        """Send or update the DHCP BOOT options for this node.

        :param task: A TaskManager instance.
        :param options: this will be a list of dicts, e.g.

                          ::

                           [{'opt_name': 'bootfile-name',
                             'opt_value': 'pxelinux.0'},
                            {'opt_name': 'server-ip-address',
                             'opt_value': '123.123.123.456'},
                            {'opt_name': 'tftp-server',
                             'opt_value': '123.123.123.123'}]
        :param vifs: a dict of Neutron port dicts to update DHCP options on.
            The keys should be Ironic port UUIDs, and the values should be
            Neutron port UUIDs
            If the value is None, will get the list of ports from the Ironic
            port objects.
        """
        if vifs is None:
            vifs = network.get_node_vif_ids(task)
        if not vifs:
            raise exception.FailedToUpdateDHCPOptOnPort(
                _("No VIFs found for node %(node)s when attempting "
                  "to update DHCP BOOT options.") %
                {'node': task.node.uuid})

        failures = []
        for port_id, port_vif in vifs.items():
            try:
                self.update_port_dhcp_opts(port_vif, options,
                                           token=task.context.auth_token)
            except exception.FailedToUpdateDHCPOptOnPort:
                failures.append(port_id)

        if failures:
            if len(failures) == len(vifs):
                raise exception.FailedToUpdateDHCPOptOnPort(_(
                    "Failed to set DHCP BOOT options for any port on node %s.")
                    % task.node.uuid)
            else:
                LOG.warning(_LW("Some errors were encountered when updating "
                                "the DHCP BOOT options for node %(node)s on "
                                "the following ports: %(ports)s."),
                            {'node': task.node.uuid, 'ports': failures})

        # TODO(adam_g): Hack to workaround bug 1334447 until we have a
        # mechanism for synchronizing events with Neutron.  We need to sleep
        # only if we are booting VMs, which is implied by SSHPower, to ensure
        # they do not boot before Neutron agents have setup sufficient DHCP
        # config for netboot.
        if isinstance(task.driver.power, ssh.SSHPower):
            LOG.debug("Waiting 15 seconds for Neutron.")
            time.sleep(15)

    def _get_fixed_ip_address(self, port_uuid, client):
        """Get a port's fixed ip address.

        :param port_uuid: Neutron port id.
        :param client: Neutron client instance.
        :returns: Neutron port ip address.
        :raises: FailedToGetIPAddressOnPort
        :raises: InvalidIPv4Address
        """
        ip_address = None
        try:
            neutron_port = client.show_port(port_uuid).get('port')
        except neutron_client_exc.NeutronClientException:
            LOG.exception(_LE("Failed to Get IP address on Neutron port %s."),
                          port_uuid)
            raise exception.FailedToGetIPAddressOnPort(port_id=port_uuid)

        fixed_ips = neutron_port.get('fixed_ips')

        # NOTE(faizan) At present only the first fixed_ip assigned to this
        # neutron port will be used, since nova allocates only one fixed_ip
        # for the instance.
        if fixed_ips:
            ip_address = fixed_ips[0].get('ip_address', None)

        if ip_address:
            if netutils.is_valid_ipv4(ip_address):
                return ip_address
            else:
                LOG.error(_LE("Neutron returned invalid IPv4 address %s."),
                          ip_address)
                raise exception.InvalidIPv4Address(ip_address=ip_address)
        else:
            LOG.error(_LE("No IP address assigned to Neutron port %s."),
                      port_uuid)
            raise exception.FailedToGetIPAddressOnPort(port_id=port_uuid)

    def _get_port_ip_address(self, task, port_uuid, client):
        """Get ip address of ironic port assigned by neutron.

        :param task: a TaskManager instance.
        :param port_uuid: ironic Node's port UUID.
        :param client: Neutron client instance.
        :returns:  Neutron port ip address associated with Node's port.
        :raises: FailedToGetIPAddressOnPort
        :raises: InvalidIPv4Address
        """

        vifs = network.get_node_vif_ids(task)
        if not vifs:
            LOG.warning(_LW("No VIFs found for node %(node)s when attempting "
                            " to get port IP address."),
                        {'node': task.node.uuid})
            raise exception.FailedToGetIPAddressOnPort(port_id=port_uuid)

        port_vif = vifs[port_uuid]

        port_ip_address = self._get_fixed_ip_address(port_vif, client)
        return port_ip_address

    def get_ip_addresses(self, task):
        """Get IP addresses for all ports in `task`.

        :param task: a TaskManager instance.
        :returns: List of IP addresses associated with task.ports.
        """
        client = _build_client(task.context.auth_token)
        failures = []
        ip_addresses = []
        for port in task.ports:
            try:
                port_ip_address = self._get_port_ip_address(task, port.uuid,
                                                            client)
                ip_addresses.append(port_ip_address)
            except (exception.FailedToGetIPAddressOnPort,
                    exception.InvalidIPv4Address):
                failures.append(port.uuid)

        if failures:
            LOG.warn(_LW("Some errors were encountered on node %(node)s"
                         " while retrieving IP address on the following"
                         " ports: %(ports)s."),
                     {'node': task.node.uuid, 'ports': failures})

        return ip_addresses

    def create_cleaning_ports(self, task):
        """Create neutron ports for each port on task.node to boot the ramdisk.

        :param task: a TaskManager instance.
        :raises: InvalidParameterValue if the cleaning network is None
        :returns: a dictionary in the form {port.uuid: neutron_port['id']}
        """
        if not CONF.neutron.cleaning_network_uuid:
            raise exception.InvalidParameterValue(_('Valid cleaning network '
                                                    'UUID not provided'))
        neutron_client = _build_client(task.context.auth_token)
        body = {
            'port': {
                'network_id': CONF.neutron.cleaning_network_uuid,
                'admin_state_up': True,
            }
        }
        ports = {}
        for ironic_port in task.ports:
            body['port']['mac_address'] = ironic_port.address
            try:
                port = neutron_client.create_port(body)
            except neutron_client_exc.ConnectionFailed as e:
                self._rollback_cleaning_ports(task)
                msg = (_('Could not create cleaning port on network %(net)s '
                         'from %(node)s. %(exc)s') %
                       {'net': CONF.neutron.cleaning_network_uuid,
                        'node': task.node.uuid,
                        'exc': e})
                LOG.exception(msg)
                raise exception.NodeCleaningFailure(msg)
            if not port.get('port') or not port['port'].get('id'):
                self._rollback_cleaning_ports(task)
                msg = (_('Failed to create cleaning ports for node '
                         '%(node)s') % task.node.uuid)
                LOG.error(msg)
                raise exception.NodeCleaningFailure(msg)
            # Match return value of get_node_vif_ids()
            ports[ironic_port.uuid] = port['port']['id']
        return ports

    def delete_cleaning_ports(self, task):
        """Deletes the neutron port created for booting the ramdisk.

        :param task: a TaskManager instance.
        """
        neutron_client = _build_client(task.context.auth_token)
        macs = [p.address for p in task.ports]
        params = {
            'network_id': CONF.neutron.cleaning_network_uuid
        }
        try:
            ports = neutron_client.list_ports(**params)
        except neutron_client_exc.ConnectionFailed as e:
            msg = (_('Could not get cleaning network vif for %(node)s '
                     'from Neutron, possible network issue. %(exc)s') %
                   {'node': task.node.uuid,
                    'exc': e})
            LOG.exception(msg)
            raise exception.NodeCleaningFailure(msg)

        # Iterate the list of Neutron port dicts, remove the ones we added
        for neutron_port in ports.get('ports', []):
            # Only delete ports using the node's mac addresses
            if neutron_port.get('mac_address') in macs:
                try:
                    neutron_client.delete_port(neutron_port.get('id'))
                except neutron_client_exc.ConnectionFailed as e:
                    msg = (_('Could not remove cleaning ports on network '
                             '%(net)s from %(node)s, possible network issue. '
                             '%(exc)s') %
                           {'net': CONF.neutron.cleaning_network_uuid,
                            'node': task.node.uuid,
                            'exc': e})
                    LOG.exception(msg)
                    raise exception.NodeCleaningFailure(msg)

    def _rollback_cleaning_ports(self, task):
        """Attempts to delete any ports created by cleaning

        Purposefully will not raise any exceptions so error handling can
        continue.

        :param task: a TaskManager instance.
        """
        try:
            self.delete_cleaning_ports(task)
        except Exception:
            # Log the error, but let the caller invoke the
            # manager.cleaning_error_handler().
            LOG.exception(_LE('Failed to rollback cleaning port '
                              'changes for node %s') % task.node.uuid)
