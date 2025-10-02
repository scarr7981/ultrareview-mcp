#!/usr/bin/env python3
import asyncio
import json
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_mcp_server():
    server_params = StdioServerParameters(
        command=".venv/bin/python3",
        args=["server.py"],
        env=None
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools_response = await session.list_tools()
            print(f"Available tools: {[tool.name for tool in tools_response.tools]}")
            print()

            print("Testing ask_codex tool...")
            result = await session.call_tool(
                "ask_codex",
                arguments={
                    "prompt": "say hello in 5 words"
                }
            )

            print("Result:")
            for content in result.content:
                print(content.text)


if __name__ == "__main__":
    asyncio.run(test_mcp_server())