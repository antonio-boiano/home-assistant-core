"""Config flow for 154_sniffer integration."""
from __future__ import annotations

import logging
import subprocess
import sys
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components import usb
from homeassistant.const import CONF_DEVICE, CONF_NAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowHandler, FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import DEFAULT_NAME, DOMAIN

CONF_DEVICE_PATH = "path"
CONF_MANUAL_PATH = "Enter Manually"

OPTIONS_INTENT_MIGRATE = "intent_migrate"
OPTIONS_INTENT_RECONFIGURE = "intent_reconfigure"


_LOGGER = logging.getLogger(__name__)


def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


try:
    pass
except ImportError:
    _LOGGER.warning("killerbee NOT installed, try to installing it")
    install("git+https://github.com/riverloopsec/killerbee.git#egg=killerbee")

from .zbid import zbId


class BaseSniffingFlow(FlowHandler):
    """Placeholder class to make tests pass."""

    _hass: HomeAssistant

    def __init__(self) -> None:
        """Initialize flow instance."""
        super().__init__()

        self._hass = None
        self._radio_mgr = zbId()
        self._title: str | None = None

    @property
    def hass(self):
        """Return hass."""
        return self._hass

    @hass.setter
    def hass(self, hass):
        """Set hass."""
        self._hass = hass
        self._radio_mgr.hass = hass

    async def async_step_choose_serial_port(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Choose a serial port."""
        ports = await self.hass.async_add_executor_job(self._radio_mgr.devlist)
        list_of_ports = [
            f"s/n: {p.dev_path or 'n/a'}" + (f" - {p.dev_desc}" if p.dev_desc else "")
            for p in ports
        ]
        # if not list_of_ports:
        #    return await self.async_step_manual_pick_radio_type()

        list_of_ports.append(CONF_MANUAL_PATH)

        if user_input is not None:
            user_selection = user_input[CONF_DEVICE_PATH]

            # if user_selection == CONF_MANUAL_PATH:
            #    return await self.async_step_manual_pick_radio_type()

            port = ports[list_of_ports.index(user_selection)]
            self._radio_mgr.dev_path = port.dev_path

            self._title = (
                f"{port.dev_desc}, s/n: {port.dev_path or 'n/a'}"
                f" - {port.manufacturer}"
                if port.manufacturer
                else ""
            )

            return await self.async_step_choose_formation_strategy()

        # Pre-select the currently configured port
        default_port = vol.UNDEFINED

        if self._radio_mgr.dev_path is not None:
            for dev_desc, port in zip(list_of_ports, ports):
                if port.dev_path == self._radio_mgr.dev_path:
                    default_port = dev_desc
                    break
            else:
                default_port = CONF_MANUAL_PATH

        schema = vol.Schema(
            {
                vol.Required(CONF_DEVICE_PATH, default=default_port): vol.In(
                    list_of_ports
                )
            }
        )
        return self.async_show_form(step_id="choose_serial_port", data_schema=schema)

    async def async_step_choose_formation_strategy(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Confirm if we are migrating adapters or just re-configuring."""

        return self.async_show_menu(
            step_id="prompt_migrate_or_reconfigure",
            menu_options=[
                OPTIONS_INTENT_RECONFIGURE,
                OPTIONS_INTENT_MIGRATE,
            ],
        )


class ConfigFlow(BaseSniffingFlow, config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for 154_sniffer."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle 15.4 forensic config flow start"""
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        return await self.async_step_choose_serial_port(user_input)

    async def async_step_usb(self, discovery_info: usb.UsbServiceInfo) -> FlowResult:
        """Handle USB Discovery."""
        device = discovery_info.device

        dev_path = await self.hass.async_add_executor_job(usb.get_serial_by_id, device)
        unique_id = f"{discovery_info.vid}:{discovery_info.pid}_{discovery_info.serial_number}_{discovery_info.manufacturer}_{discovery_info.description}"
        if (
            #    await self.validate_device_errors(dev_path=dev_path, unique_id=unique_id)
            #    is Noneù
            True
        ):
            self._device = dev_path
            return await self.async_step_usb_confirm()
        return self.async_abort(reason="cannot_connect")

    async def async_step_usb_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle USB Discovery confirmation."""
        if user_input is not None:
            return self.async_create_entry(
                title=user_input.get(CONF_NAME, DEFAULT_NAME),
                data={CONF_DEVICE: self._device},
            )
        self._set_confirm_only()
        return self.async_show_form(step_id="usb_confirm")


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
