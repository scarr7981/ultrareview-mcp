#!/usr/bin/env python3
import asyncio
import subprocess
import json
import re
from typing import Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


app = Server("ultrareview-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ask_codex",
            description="Execute a Codex CLI command and get feedback. Codex is an AI coding assistant that can provide code reviews, suggestions, and analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The prompt or question to ask Codex"
                    },
                    "model": {
                        "type": "string",
                        "description": "Model to use (e.g., o4-mini, o3-mini). Uses CLI default if not specified"
                    },
                    "full_auto": {
                        "type": "boolean",
                        "description": "Automatically approve all edits and commands (workspace-write sandbox)",
                        "default": False
                    },
                    "json": {
                        "type": "boolean",
                        "description": "Print events to stdout as JSONL",
                        "default": False
                    },
                    "output_schema": {
                        "type": "string",
                        "description": "Path to JSON schema file describing model's final response shape"
                    },
                    "sandbox": {
                        "type": "string",
                        "description": "Sandbox policy: read-only, workspace-write, or danger-full-access",
                        "enum": ["read-only", "workspace-write", "danger-full-access"]
                    },
                    "working_directory": {
                        "type": "string",
                        "description": "Directory to run Codex in (uses --cd flag). Defaults to current directory."
                    }
                },
                "required": ["prompt"]
            }
        ),
        Tool(
            name="ask_copilot",
            description="Execute a GitHub Copilot CLI command and get feedback. GitHub Copilot is an AI-powered coding assistant that can provide code suggestions, reviews, and analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The prompt or question to ask GitHub Copilot"
                    },
                    "model": {
                        "type": "string",
                        "description": "Model to use (claude-sonnet-4.5, claude-sonnet-4, or gpt-5). Uses CLI default if not specified"
                    },
                    "allow_all_tools": {
                        "type": "boolean",
                        "description": "Allow all tools to run automatically without confirmation",
                        "default": False
                    },
                    "allow_tool": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific tools to allow"
                    },
                    "deny_tool": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific tools to deny (takes precedence over allow_tool)"
                    },
                    "add_dir": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of directories to add to the allowed list for file access"
                    },
                    "log_level": {
                        "type": "string",
                        "description": "Set the log level",
                        "enum": ["error", "warning", "info", "debug", "all", "default", "none"]
                    },
                    "no_color": {
                        "type": "boolean",
                        "description": "Disable all color output",
                        "default": False
                    }
                },
                "required": ["prompt"]
            }
        ),
        Tool(
            name="ask_claude",
            description="Execute a Claude CLI command and get feedback. Claude Code is an AI-powered coding assistant that can provide code analysis, suggestions, and development assistance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The prompt or question to ask Claude"
                    },
                    "model": {
                        "type": "string",
                        "description": "Model to use (e.g., 'sonnet', 'opus', or full model name like 'claude-sonnet-4-20250514'). Uses CLI default if not specified"
                    },
                    "fallback_model": {
                        "type": "string",
                        "description": "Enable automatic fallback to specified model when default model is overloaded (only works with print mode)"
                    },
                    "print_mode": {
                        "type": "boolean",
                        "description": "Print response and exit (non-interactive mode). Defaults to True for MCP usage"
                    },
                    "output_format": {
                        "type": "string",
                        "description": "Output format (only works with print mode)",
                        "enum": ["text", "json", "stream-json"]
                    },
                    "input_format": {
                        "type": "string",
                        "description": "Input format (only works with print mode)",
                        "enum": ["text", "stream-json"]
                    },
                    "permission_mode": {
                        "type": "string",
                        "description": "Permission mode to use for the session",
                        "enum": ["acceptEdits", "bypassPermissions", "default", "plan"]
                    },
                    "allowed_tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of tool names to allow (e.g. 'Bash(git:*)', 'Edit')"
                    },
                    "disallowed_tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of tool names to deny (e.g. 'Bash(git:*)', 'Edit')"
                    },
                    "add_dir": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Additional directories to allow tool access to"
                    },
                    "append_system_prompt": {
                        "type": "string",
                        "description": "Append a system prompt to the default system prompt"
                    },
                    "debug": {
                        "type": "boolean",
                        "description": "Enable debug mode",
                        "default": False
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Enable verbose mode",
                        "default": False
                    },
                    "dangerously_skip_permissions": {
                        "type": "boolean",
                        "description": "Bypass all permission checks (recommended only for sandboxes)",
                        "default": False
                    }
                },
                "required": ["prompt"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "ask_codex":
        return await handle_codex(arguments)
    elif name == "ask_copilot":
        return await handle_copilot(arguments)
    elif name == "ask_claude":
        return await handle_claude(arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")


async def handle_codex(arguments: dict) -> list[TextContent]:
    prompt = arguments.get("prompt")
    if not prompt:
        raise ValueError("prompt is required")

    cmd = ["codex", "exec", prompt]

    model = arguments.get("model")
    if model:
        cmd.extend(["--model", model])

    if arguments.get("full_auto", False):
        cmd.append("--full-auto")

    if arguments.get("json", False):
        cmd.append("--json")

    output_schema = arguments.get("output_schema")
    if output_schema:
        cmd.extend(["--output-schema", output_schema])

    sandbox = arguments.get("sandbox")
    if sandbox:
        cmd.extend(["--sandbox", sandbox])

    working_directory = arguments.get("working_directory")
    if working_directory:
        cmd.extend(["--cd", working_directory])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0:
            return [TextContent(
                type="text",
                text=f"Codex command failed with exit code {result.returncode}:\n{output}"
            )]

        model_used = None
        model_match = re.search(r'model: (.+)', output)
        if model_match:
            model_used = model_match.group(1).strip()

        response_header = f"**Response from Codex"
        if model_used:
            response_header += f" ({model_used})"
        response_header += "**\n\n"

        return [TextContent(
            type="text",
            text=response_header + output
        )]

    except subprocess.TimeoutExpired:
        return [TextContent(
            type="text",
            text="Codex command timed out after 5 minutes"
        )]
    except FileNotFoundError:
        return [TextContent(
            type="text",
            text="Error: codex command not found. Please ensure Codex CLI is installed and in PATH."
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error executing codex: {str(e)}"
        )]


async def handle_copilot(arguments: dict) -> list[TextContent]:
    prompt = arguments.get("prompt")
    if not prompt:
        raise ValueError("prompt is required")

    cmd = ["copilot", "--prompt", prompt]

    model = arguments.get("model")
    if model:
        cmd.extend(["--model", model])

    if arguments.get("allow_all_tools", False):
        cmd.append("--allow-all-tools")

    allow_tools = arguments.get("allow_tool", [])
    for tool in allow_tools:
        cmd.extend(["--allow-tool", tool])

    deny_tools = arguments.get("deny_tool", [])
    for tool in deny_tools:
        cmd.extend(["--deny-tool", tool])

    add_dirs = arguments.get("add_dir", [])
    for directory in add_dirs:
        cmd.extend(["--add-dir", directory])

    log_level = arguments.get("log_level")
    if log_level:
        cmd.extend(["--log-level", log_level])

    if arguments.get("no_color", False):
        cmd.append("--no-color")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0:
            return [TextContent(
                type="text",
                text=f"GitHub Copilot command failed with exit code {result.returncode}:\n{output}"
            )]

        response_header = f"**Response from GitHub Copilot**\n\n"

        return [TextContent(
            type="text",
            text=response_header + output
        )]

    except subprocess.TimeoutExpired:
        return [TextContent(
            type="text",
            text="GitHub Copilot command timed out after 5 minutes"
        )]
    except FileNotFoundError:
        return [TextContent(
            type="text",
            text="Error: copilot command not found. Please ensure GitHub Copilot CLI is installed and in PATH."
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error executing GitHub Copilot: {str(e)}"
        )]


async def handle_claude(arguments: dict) -> list[TextContent]:
    prompt = arguments.get("prompt")
    if not prompt:
        raise ValueError("prompt is required")

    # Use --print by default for non-interactive mode unless specified otherwise
    print_mode = arguments.get("print_mode", True)
    
    if print_mode:
        cmd = ["claude", "--print", prompt]
    else:
        cmd = ["claude", prompt]

    model = arguments.get("model")
    if model:
        cmd.extend(["--model", model])

    fallback_model = arguments.get("fallback_model")
    if fallback_model and print_mode:
        cmd.extend(["--fallback-model", fallback_model])

    output_format = arguments.get("output_format")
    if output_format and print_mode:
        cmd.extend(["--output-format", output_format])

    input_format = arguments.get("input_format")
    if input_format and print_mode:
        cmd.extend(["--input-format", input_format])

    permission_mode = arguments.get("permission_mode")
    if permission_mode:
        cmd.extend(["--permission-mode", permission_mode])

    allowed_tools = arguments.get("allowed_tools", [])
    for tool in allowed_tools:
        cmd.extend(["--allowedTools", tool])

    disallowed_tools = arguments.get("disallowed_tools", [])
    for tool in disallowed_tools:
        cmd.extend(["--disallowedTools", tool])

    add_dirs = arguments.get("add_dir", [])
    for directory in add_dirs:
        cmd.extend(["--add-dir", directory])

    append_system_prompt = arguments.get("append_system_prompt")
    if append_system_prompt:
        cmd.extend(["--append-system-prompt", append_system_prompt])

    if arguments.get("debug", False):
        cmd.append("--debug")

    if arguments.get("verbose", False):
        cmd.append("--verbose")

    if arguments.get("dangerously_skip_permissions", False):
        cmd.append("--dangerously-skip-permissions")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0:
            return [TextContent(
                type="text",
                text=f"Claude CLI command failed with exit code {result.returncode}:\n{output}"
            )]

        response_header = f"**Response from Claude CLI**\n\n"

        return [TextContent(
            type="text",
            text=response_header + output
        )]

    except subprocess.TimeoutExpired:
        return [TextContent(
            type="text",
            text="Claude CLI command timed out after 5 minutes"
        )]
    except FileNotFoundError:
        return [TextContent(
            type="text",
            text="Error: claude command not found. Please ensure Claude CLI is installed and in PATH."
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"Error executing Claude CLI: {str(e)}"
        )]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())