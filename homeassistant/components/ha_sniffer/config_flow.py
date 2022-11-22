"""Config flow for 154_sniffer integration."""
from __future__ import annotations

import logging

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowHandler
from homeassistant.exceptions import HomeAssistantError

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class BaseSniffingFlow(FlowHandler):
    """Placeholder class to make tests pass."""

    def __init__(self) -> None:
        """Initialize flow instance."""
        super().__init__()

        self._hass = None
        # self._radio_mgr = ZhaRadioManager()
        self._title: str | None = None


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for 154_sniffer."""

    VERSION = 1


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
