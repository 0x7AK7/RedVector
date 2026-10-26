"""Exercise the actual registered Nmap handler; HTTP is the isolated boundary."""
import unittest
from unittest.mock import Mock

class RecoveryControl(unittest.TestCase):
    def test_default_preserved_but_confined_client_can_disable_recovery(self):
        from redvector_mcp import setup_mcp_server
        client=Mock();client.safe_post.return_value={"success":False}
        server=setup_mcp_server(client)
        handler=server._tool_manager.get_tool("nmap_scan").fn
        handler(target="192.0.2.1")
        self.assertIs(client.safe_post.call_args.args[1]["use_recovery"],True)
        handler(target="192.0.2.1",use_recovery=False)
        self.assertIs(client.safe_post.call_args.args[1]["use_recovery"],False)
        self.assertEqual(len(server._tool_manager.list_tools()),328)
