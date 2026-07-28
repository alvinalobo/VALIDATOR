import importlib
import inspect
import pkgutil

from app.connector.base_connector import BaseConnector, ConnectorRegistry


def load_plugins():
    """
    Dynamically discover and register all connector plugins.
    """

    package = importlib.import_module("app.connector")

    for _, module_name, _ in pkgutil.iter_modules(package.__path__):

        # Ignore non-plugin modules
        if module_name in [
            "base_connector",
            "exceptions",
            "plugin_loader",
            "__pycache__"
        ]:
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
                    print(f"[PluginLoader] Registered: {vendor}")
                except Exception as e:
                    print(f"[PluginLoader] Failed to register {vendor}: {e}")