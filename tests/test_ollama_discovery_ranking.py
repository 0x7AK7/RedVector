"""Exact operator-named tools must survive discovery across large verbose catalogs."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from redvector_ollama_agent import Agent
from redvector_ollama_policy import Policy

class DiscoveryRanking(unittest.TestCase):
    def test_explicit_health_tool_is_not_displaced_by_verbose_unreviewed_tools(self):
        prompt=("Call the read-only server_health tool once. Then summarize the actual server status "
                "and exact version returned by that tool in one short English sentence. "
                "Do not scan a target, call other assessment tools, or invent results.")
        catalog={f"autonomous_tool_{i}":SimpleNamespace(name=f"autonomous_tool_{i}",
                  description=prompt+" "+" ".join(["assessment analysis operation"]*50),
                  inputSchema={"type":"object","properties":{}}) for i in range(12)}
        catalog["server_health"]=SimpleNamespace(name="server_health",description="Check server health",
                                                inputSchema={"type":"object","properties":{}})
        agent=Agent(Mock(),"local",Mock(),catalog,Policy(),lambda _:False,lambda _:None)
        found=agent.select(prompt)
        self.assertEqual(found[0]["name"],"server_health")
        self.assertIn("server_health",{item["function"]["name"] for item in agent.schemas()})
