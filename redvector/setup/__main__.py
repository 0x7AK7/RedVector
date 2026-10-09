"""Entrypoint: ``python -m redvector.setup [--flags]``.

Delegated to by the platform launchers after they bootstrap the virtualenv. Exits
10 to tell the launcher to start RedVector normally, 0 when a setup command was
handled. See redvector.setup.manager for the full contract.
"""
import sys

from redvector.setup.manager import AIIntegrationSetupManager


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    return AIIntegrationSetupManager().run(argv)


if __name__ == "__main__":
    sys.exit(main())
