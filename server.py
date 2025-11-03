#!/usr/bin/env python3
import asyncio
import subprocess
import json
import re
import logging
import os
import traceback
from pathlib import Path
from datetime import datetime
from typing import Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


# Setup logging
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Create logger
logger = logging.getLogger("ultrareview-mcp")
logger.setLevel(logging.DEBUG)

# File handler with rotation by date
log_file = LOG_DIR / f"ultrareview-mcp-{datetime.now().strftime('%Y%m%d')}.log"
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.DEBUG)

# Console handler for errors only
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)

# Formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

app = Server("ultrareview-mcp")
logger.info("UltraReview MCP Server initialized")


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
                        "description": "Model to use (e.g., o4-mini, o3-mini). IMPORTANT: Only specify this parameter if you have a deliberate, specific reason to override the user's CLI default model. In most cases, you should omit this parameter and let the CLI use the default. Uses CLI default if not specified."
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
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Enable verbose debugging output in response",
                        "default": False
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
                        "description": "Model to use (claude-sonnet-4.5, claude-sonnet-4, or gpt-5). IMPORTANT: Only specify this parameter if you have a deliberate, specific reason to override the user's CLI default model. In most cases, you should omit this parameter and let the CLI use the default. Uses CLI default if not specified."
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
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Enable verbose debugging output in response",
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
                        "description": "Model to use (e.g., 'sonnet', 'opus', or full model name like 'claude-sonnet-4-20250514'). IMPORTANT: Only specify this parameter if you have a deliberate, specific reason to override the user's CLI default model. In most cases, you should omit this parameter and let the CLI use the default. Uses CLI default if not specified."
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
                        "description": "Enable verbose debugging output in response",
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
    logger.info(f"Tool called: {name}")
    logger.debug(f"Arguments: {json.dumps(arguments, indent=2)}")

    if name == "ask_codex":
        return await handle_codex(arguments)
    elif name == "ask_copilot":
        return await handle_copilot(arguments)
    elif name == "ask_claude":
        return await handle_claude(arguments)
    else:
        logger.error(f"Unknown tool: {name}")
        raise ValueError(f"Unknown tool: {name}")


def build_debug_info(tool_name: str, cmd: list, arguments: dict) -> str:
    """Build debug information string for verbose output"""
    return f"""**Debug Info for {tool_name}**

Command: {' '.join(cmd)}
Working directory: {os.getcwd()}
PATH: {os.environ.get('PATH', 'NOT SET')}
Arguments: {json.dumps(arguments, indent=2)}

---
"""


async def handle_codex(arguments: dict) -> list[TextContent]:
    prompt = arguments.get("prompt")
    verbose = arguments.get("verbose", False)

    if not prompt:
        logger.error("Codex: prompt is required but not provided")
        raise ValueError("prompt is required")

    logger.info(f"Codex: Executing prompt (length: {len(prompt)})")

    cmd = ["codex", "exec", prompt]

    model = arguments.get("model")
    if model:
        cmd.extend(["--model", model])
        logger.debug(f"Codex: Using model: {model}")

    if arguments.get("full_auto", False):
        cmd.append("--full-auto")
        logger.debug("Codex: full_auto enabled")

    if arguments.get("json", False):
        cmd.append("--json")
        logger.debug("Codex: JSON output enabled")

    output_schema = arguments.get("output_schema")
    if output_schema:
        cmd.extend(["--output-schema", output_schema])
        logger.debug(f"Codex: Using output schema: {output_schema}")

    sandbox = arguments.get("sandbox")
    if sandbox:
        cmd.extend(["--sandbox", sandbox])
        logger.debug(f"Codex: Sandbox mode: {sandbox}")

    working_directory = arguments.get("working_directory")
    if working_directory:
        cmd.extend(["--cd", working_directory])
        logger.debug(f"Codex: Working directory: {working_directory}")

    debug_info = build_debug_info("Codex", cmd, arguments) if verbose else ""

    logger.debug(f"Codex: Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        logger.info(f"Codex: Command completed with return code {result.returncode}")

        if verbose:
            debug_info += f"""
Subprocess completed:
- Return code: {result.returncode}
- stdout length: {len(result.stdout) if result.stdout else 0}
- stderr length: {len(result.stderr) if result.stderr else 0}

"""

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0:
            logger.warning(f"Codex: Command failed with exit code {result.returncode}")
            logger.debug(f"Codex: Error output: {output[:500]}")
            return [TextContent(
                type="text",
                text=f"{debug_info}Codex command failed with exit code {result.returncode}:\n{output}"
            )]

        model_used = None
        model_match = re.search(r'model: (.+)', output)
        if model_used:
            logger.debug(f"Codex: Model used: {model_used}")

        response_header = f"**Response from Codex"
        if model_used:
            response_header += f" ({model_used})"
        response_header += "**\n\n"

        logger.info("Codex: Successfully completed request")
        return [TextContent(
            type="text",
            text=debug_info + response_header + output
        )]

    except subprocess.TimeoutExpired:
        logger.error("Codex: Command timed out after 5 minutes")
        return [TextContent(
            type="text",
            text=f"{debug_info}Codex command timed out after 5 minutes"
        )]
    except FileNotFoundError as e:
        logger.error(f"Codex: Command not found: {str(e)}")
        return [TextContent(
            type="text",
            text=f"{debug_info}Error: codex command not found. Please ensure Codex CLI is installed and in PATH.\n\nDetails: {str(e)}"
        )]
    except Exception as e:
        logger.error(f"Codex: Unexpected error: {str(e)}")
        logger.debug(f"Codex: Traceback: {traceback.format_exc()}")
        return [TextContent(
            type="text",
            text=f"{debug_info}Error executing codex: {str(e)}\n\nException type: {type(e).__name__}\n\nTraceback:\n{traceback.format_exc()}"
        )]


async def handle_copilot(arguments: dict) -> list[TextContent]:
    prompt = arguments.get("prompt")
    verbose = arguments.get("verbose", False)

    if not prompt:
        logger.error("Copilot: prompt is required but not provided")
        raise ValueError("prompt is required")

    logger.info(f"Copilot: Executing prompt (length: {len(prompt)})")

    cmd = ["copilot", "--prompt", prompt]

    model = arguments.get("model")
    if model:
        cmd.extend(["--model", model])
        logger.debug(f"Copilot: Using model: {model}")

    if arguments.get("allow_all_tools", False):
        cmd.append("--allow-all-tools")
        logger.debug("Copilot: allow_all_tools enabled")

    allow_tools = arguments.get("allow_tool", [])
    for tool in allow_tools:
        cmd.extend(["--allow-tool", tool])
        logger.debug(f"Copilot: Allowing tool: {tool}")

    deny_tools = arguments.get("deny_tool", [])
    for tool in deny_tools:
        cmd.extend(["--deny-tool", tool])
        logger.debug(f"Copilot: Denying tool: {tool}")

    add_dirs = arguments.get("add_dir", [])
    for directory in add_dirs:
        cmd.extend(["--add-dir", directory])
        logger.debug(f"Copilot: Adding directory: {directory}")

    log_level = arguments.get("log_level")
    if log_level:
        cmd.extend(["--log-level", log_level])
        logger.debug(f"Copilot: Log level: {log_level}")

    if arguments.get("no_color", False):
        cmd.append("--no-color")
        logger.debug("Copilot: no_color enabled")

    debug_info = build_debug_info("GitHub Copilot", cmd, arguments) if verbose else ""

    logger.debug(f"Copilot: Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        logger.info(f"Copilot: Command completed with return code {result.returncode}")

        if verbose:
            debug_info += f"""
Subprocess completed:
- Return code: {result.returncode}
- stdout length: {len(result.stdout) if result.stdout else 0}
- stderr length: {len(result.stderr) if result.stderr else 0}

"""

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0:
            logger.warning(f"Copilot: Command failed with exit code {result.returncode}")
            logger.debug(f"Copilot: Error output: {output[:500]}")
            return [TextContent(
                type="text",
                text=f"{debug_info}GitHub Copilot command failed with exit code {result.returncode}:\n\n{output}"
            )]

        response_header = f"**Response from GitHub Copilot**\n\n"

        logger.info("Copilot: Successfully completed request")
        return [TextContent(
            type="text",
            text=debug_info + response_header + output
        )]

    except subprocess.TimeoutExpired:
        logger.error("Copilot: Command timed out after 5 minutes")
        return [TextContent(
            type="text",
            text=f"{debug_info}GitHub Copilot command timed out after 5 minutes"
        )]
    except FileNotFoundError as e:
        logger.error(f"Copilot: Command not found: {str(e)}")
        return [TextContent(
            type="text",
            text=f"{debug_info}Error: copilot command not found. Please ensure GitHub Copilot CLI is installed and in PATH.\n\nDetails: {str(e)}"
        )]
    except Exception as e:
        logger.error(f"Copilot: Unexpected error: {str(e)}")
        logger.debug(f"Copilot: Traceback: {traceback.format_exc()}")
        return [TextContent(
            type="text",
            text=f"{debug_info}Error executing GitHub Copilot: {str(e)}\n\nException type: {type(e).__name__}\n\nTraceback:\n{traceback.format_exc()}"
        )]


async def handle_claude(arguments: dict) -> list[TextContent]:
    prompt = arguments.get("prompt")
    verbose = arguments.get("verbose", False)

    if not prompt:
        logger.error("Claude: prompt is required but not provided")
        raise ValueError("prompt is required")

    logger.info(f"Claude: Executing prompt (length: {len(prompt)})")

    # Use --print by default for non-interactive mode unless specified otherwise
    print_mode = arguments.get("print_mode", True)

    if print_mode:
        cmd = ["claude", "--print", prompt]
    else:
        cmd = ["claude", prompt]

    model = arguments.get("model")
    if model:
        cmd.extend(["--model", model])
        logger.debug(f"Claude: Using model: {model}")

    fallback_model = arguments.get("fallback_model")
    if fallback_model and print_mode:
        cmd.extend(["--fallback-model", fallback_model])
        logger.debug(f"Claude: Fallback model: {fallback_model}")

    output_format = arguments.get("output_format")
    if output_format and print_mode:
        cmd.extend(["--output-format", output_format])
        logger.debug(f"Claude: Output format: {output_format}")

    input_format = arguments.get("input_format")
    if input_format and print_mode:
        cmd.extend(["--input-format", input_format])
        logger.debug(f"Claude: Input format: {input_format}")

    permission_mode = arguments.get("permission_mode")
    if permission_mode:
        cmd.extend(["--permission-mode", permission_mode])
        logger.debug(f"Claude: Permission mode: {permission_mode}")

    allowed_tools = arguments.get("allowed_tools", [])
    for tool in allowed_tools:
        cmd.extend(["--allowedTools", tool])
        logger.debug(f"Claude: Allowing tool: {tool}")

    disallowed_tools = arguments.get("disallowed_tools", [])
    for tool in disallowed_tools:
        cmd.extend(["--disallowedTools", tool])
        logger.debug(f"Claude: Disallowing tool: {tool}")

    add_dirs = arguments.get("add_dir", [])
    for directory in add_dirs:
        cmd.extend(["--add-dir", directory])
        logger.debug(f"Claude: Adding directory: {directory}")

    append_system_prompt = arguments.get("append_system_prompt")
    if append_system_prompt:
        cmd.extend(["--append-system-prompt", append_system_prompt])
        logger.debug("Claude: System prompt appended")

    if arguments.get("debug", False):
        cmd.append("--debug")
        logger.debug("Claude: debug mode enabled")

    # Note: verbose in Claude CLI is different from our verbose debug output
    if arguments.get("verbose", False):
        cmd.append("--verbose")
        logger.debug("Claude: verbose mode enabled")

    if arguments.get("dangerously_skip_permissions", False):
        cmd.append("--dangerously-skip-permissions")
        logger.warning("Claude: dangerously_skip_permissions enabled")

    debug_info = build_debug_info("Claude CLI", cmd, arguments) if verbose else ""

    logger.debug(f"Claude: Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        logger.info(f"Claude: Command completed with return code {result.returncode}")

        if verbose:
            debug_info += f"""
Subprocess completed:
- Return code: {result.returncode}
- stdout length: {len(result.stdout) if result.stdout else 0}
- stderr length: {len(result.stderr) if result.stderr else 0}

"""

        output = result.stdout if result.stdout else result.stderr

        if result.returncode != 0:
            logger.warning(f"Claude: Command failed with exit code {result.returncode}")
            logger.debug(f"Claude: Error output: {output[:500]}")
            return [TextContent(
                type="text",
                text=f"{debug_info}Claude CLI command failed with exit code {result.returncode}:\n{output}"
            )]

        response_header = f"**Response from Claude CLI**\n\n"

        logger.info("Claude: Successfully completed request")
        return [TextContent(
            type="text",
            text=debug_info + response_header + output
        )]

    except subprocess.TimeoutExpired:
        logger.error("Claude: Command timed out after 5 minutes")
        return [TextContent(
            type="text",
            text=f"{debug_info}Claude CLI command timed out after 5 minutes"
        )]
    except FileNotFoundError as e:
        logger.error(f"Claude: Command not found: {str(e)}")
        return [TextContent(
            type="text",
            text=f"{debug_info}Error: claude command not found. Please ensure Claude CLI is installed and in PATH.\n\nDetails: {str(e)}"
        )]
    except Exception as e:
        logger.error(f"Claude: Unexpected error: {str(e)}")
        logger.debug(f"Claude: Traceback: {traceback.format_exc()}")
        return [TextContent(
            type="text",
            text=f"{debug_info}Error executing Claude CLI: {str(e)}\n\nException type: {type(e).__name__}\n\nTraceback:\n{traceback.format_exc()}"
        )]


async def main():
    logger.info("Starting MCP server")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    logger.info("UltraReview MCP Server starting up")
    asyncio.run(main())
