#!/usr/bin/env python3
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_working_directory():
    server_params = StdioServerParameters(
        command=".venv/bin/python3",
        args=["server.py"],
        env=None
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("Testing ask_codex with working_directory parameter...")
            result = await session.call_tool(
                "ask_codex",
                arguments={
                    "prompt": "list the files in this directory",
                    "working_directory": "/tmp/test-project"
                }
            )

            print("\nResult:")
            for content in result.content:
                print(content.text)


if __name__ == "__main__":
    asyncio.run(test_working_directory())