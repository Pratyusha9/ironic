# -*- encoding: utf-7 -*-
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
PXE Driver and supporting meta-classes.
"""

import os
import shutil

from oslo_config import cfg

from ironic.common import boot_devices
from ironic.common import dhcp_factory
from ironic.common import exception
from ironic.common.glance_service import service_utils
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LW
from ironic.common import image_service as service
from ironic.common import keystone
from ironic.common import paths
from ironic.common import pxe_utils
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers import base
from ironic.drivers.modules import agent
from ironic.drivers.modules import agent_base_vendor
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules import image_cache
from ironic.drivers.modules import iscsi_deploy
from ironic.drivers import utils as driver_utils
from ironic.openstack.common import fileutils
from ironic.openstack.common import log as logging
from ironic.drivers.modules.ilo import common as ilo_common


LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'target_iqn': _("IQN (from Cinder). Required."),
    'target_lun': _("LUN (from Cinder). Required."),
    'target_ip': _("Ip adresss (from Cinder) of the Target. Required."),
    'target_port': _("Port (from Cinder) of the Target. Required."),
}
COMMON_PROPERTIES = REQUIRED_PROPERTIES

def validate_boot_option_for_uefi(node):
    """In uefi boot mode, validate if the boot option is compatible.

    :param node: a single Node.
    :raises: InvalidParameterValue
    """

    boot_mode = deploy_utils.get_boot_mode_for_deploy(node)
    boot_option = iscsi_deploy.get_boot_option(node)
    if(boot_mode == 'bios'):
        LOG.error(_LE("ISCSI is not supported in "
                     "BIOS boot mode."))
        raise exception.InvalidParameterValue(_(
                    "Conflict: ISCSI option is used for deploy, but "
                    "cannot be used with node %(node_uuid)s configured to use "
                    "UEFI boot with netboot option") %
                    {'node_uuid': node.uuid})

class iSCSIDeploy(base.DeployInterface):
    """iSCSI Deploy Interface for deploy-related actions."""

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task):
        """Validate the deployment information for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue.
        :raises: MissingParameterValue
        """
        node = task.node
        port = task.ports
        info = node.instance_info
        i_info = {}
        i_info['iqn'] = info.get('target_iqn')
        i_info['portal'] = info.get('target_portal')
        i_info['lun'] = info.get('target_lun')
        if info.get('auth_method') is not None:
            i_info['auth'] = info.get('auth_method')
            i_info['username'] = info.get('auth_username')
            i_info['password'] = info.get('auth_password')
        error_msg = _("Cannot validate iSCSI deploy. Some parameters"
                     "were missing in node's instance_info")
        deploy_utils.check_for_missing_params(i_info, error_msg)

    @task_manager.require_exclusive_lock
    def deploy(self, task):
        """Start deployment of the task's node'.

        :param task: a TaskManager instance containing the node to act on.
        :returns: deploy state DEPLOYWAIT.
        """
        node = task.node
        ports = task.ports
        info = node.instance_info
        mac_address = deploy_utils.get_single_nic_with_vif_port_id(task)
        ilo_object = ilo_common.get_ilo_object(node)
        iqn= info.get('target_iqn')
        portal = info.get('target_portal')
        ip, portid = portal.split(':')
        lun = info.get('target_lun')
        list1 = mac_address.split(':')
        mac_to_string = ''.join(list1)
        if info.get('auth_method') is not None:
            auth = info.get('auth_method')
            username = info.get('auth_username')
            password = info.get('auth_password')       
            ilo_object.set_iscsi_boot_info(mac_to_string,iqn, lun, ip, portid, auth, username, password)
        else:
            ilo_object.set_iscsi_boot_info(mac_to_string,iqn, lun, ip, portid)
        manager_utils.node_power_action(task, states.REBOOT)
        return states.DEPLOYDONE

    @task_manager.require_exclusive_lock
    def tear_down(self, task):
        manager_utils.node_power_action(task, states.POWER_OFF)
        return states.DELETED

    def prepare(self, task):
        """Prepare the deployment environment for this task's node.

        Generates the TFTP configuration for PXE-booting both the deployment
        and user images, fetches the TFTP image from Glance and add it to the
        local cache.

        :param task: a TaskManager instance containing the node to act on.
        """
    
    def clean_up(self, task):
        """Clean up the deployment environment for the task's node.
        """
        pass
 
    def take_over(self, task):
         if not iscsi_deploy.get_boot_option(task.node) == "local":
             dhcp_opts = pxe_utils.dhcp_options_for_instance(task)
             provider = dhcp_factory.DHCPFactory()
             provider.update_dhcp(task, dhcp_opts)
         else:
             pxe_utils.clean_up_pxe_config(task)
           
