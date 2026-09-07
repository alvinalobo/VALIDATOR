import importlib
import inspect
import logging
import pkgutil

from app.connector.base_connector import BaseConnector, ConnectorRegistry

logger = logging.getLogger(__name__)

# Modules that are part of the framework itself, not plugins.
_NON_PLUGIN_MODULES = {
    "base_connector",
    "config_validation",
    "exceptions",
    "plugin_loader",
    "retry",
    "__pycache__",
}


def load_plugins():
    """
    Dynamically discover and register all connector plugins.
    """

    package = importlib.import_module("app.connector")

    for _, module_name, _ in pkgutil.iter_modules(package.__path__):

        # Ignore non-plugin modules
        if module_name in _NON_PLUGIN_MODULES:
            continue

        module = importlib.import_module(f"app.connector.{module_name}")

        for _, obj in inspect.getmembers(module, inspect.isclass):

            if (
                issubclass(obj, BaseConnector)
                and obj is not BaseConnector
            ):

                vendor = module_name.replace("_connector", "")

                try:
                    ConnectorRegistry.register(vendor, obj)
                    logger.info("[PluginLoader] Registered: %s", vendor)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error(
                        "[PluginLoader] Failed to register %s: %s",
                        vendor,
                        exc,
                    )