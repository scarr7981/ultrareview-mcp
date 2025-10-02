# UltraReview MCP Server

A Model Context Protocol (MCP) server that integrates Codex CLI, GitHub Copilot CLI, and Claude CLI with Claude Code for AI-powered code reviews and feedback.

## ⚠️ IMPORTANT SAFETY WARNING

**USE AT YOUR OWN RISK** - This tool provides AI models with direct access to execute commands on your system through CLI tools. The AI models may:

- **Execute potentially dangerous commands** if given inappropriate permissions
- **Modify, delete, or create files** in your filesystem 
- **Make network requests** or interact with external services
- **Install software** or modify system configurations
- **Access sensitive data** in your project directories

### Safety Recommendations

🔒 **Always run in isolated environments** (Docker containers, VMs, or sandboxed systems)  
🔒 **Never use on production systems** or systems with sensitive data  
🔒 **Review all generated commands** before execution when possible  
🔒 **Use restrictive permission modes** and directory limitations  
🔒 **Monitor AI outputs carefully** for unexpected or dangerous behavior  
🔒 **Keep backups** of important work before using AI assistance tools

## Features

- Execute Codex CLI commands through MCP
- Execute GitHub Copilot CLI commands through MCP
- Execute Claude CLI commands through MCP
- Support for multiple models across all platforms
- Structured JSON output support
- Auto-approval and quiet modes
- Advanced tool permission management
- Integration with Claude Code

## Prerequisites

- Python 3.10+
- [Codex CLI](https://github.com/codex-cli) installed and in PATH
- [GitHub Copilot CLI](https://github.com/github/gh-copilot) installed and in PATH
- [Claude CLI](https://claude.ai/code) installed and in PATH
- Claude Desktop or compatible MCP client

**⚠️ Note**: Each CLI tool has its own authentication requirements and safety considerations. Ensure you understand the permissions and capabilities of each tool before use.

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Make the server executable:
```bash
chmod +x server.py
```

## Configuration

Add to your Claude Desktop config:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ultrareview": {
      "command": "/home/user/dev/ultrareview-mcp/.venv/bin/python3",
      "args": ["/home/user/dev/ultrareview-mcp/server.py"]
    }
  }
}
```

**Important:** Use the full absolute path to the venv Python interpreter and server.py file.

## Usage

In Claude Code, you can now use the MCP tools:

**Codex:**
```
"Ask Codex for feedback on this code"
"Ask Codex to review PR 81"
"Ask Codex for five words about apples"
```

**GitHub Copilot:**
```
"Ask Copilot for code suggestions"
"Ask Copilot to explain this function"
"Ask Copilot to optimize this algorithm"
```

**Claude CLI:**
```
"Ask Claude to analyze this codebase"
"Ask Claude for debugging help"
"Ask Claude to suggest architectural improvements"
```

The MCP server will execute the appropriate CLI command and return the results.

## Tool Parameters

### ask_codex
- **prompt** (required): The question or prompt for Codex
- **model** (optional): Model to use (uses CLI default if not specified)
- **full_auto** (optional): Auto-approve all edits and commands (workspace-write sandbox)
- **json** (optional): Print events to stdout as JSONL
- **output_schema** (optional): Path to JSON schema file for structured output
- **sandbox** (optional): Sandbox policy (read-only, workspace-write, danger-full-access)
- **working_directory** (optional): Directory to run Codex in

### ask_copilot
- **prompt** (required): The question or prompt for GitHub Copilot
- **model** (optional): Model to use (uses CLI default if not specified)
- **allow_all_tools** (optional): Allow all tools to run automatically without confirmation
- **allow_tool** (optional): List of specific tools to allow
- **deny_tool** (optional): List of specific tools to deny (takes precedence over allow_tool)
- **add_dir** (optional): List of directories to add to the allowed list for file access
- **log_level** (optional): Set the log level (error, warning, info, debug, all, default, none)
- **no_color** (optional): Disable all color output

### ask_claude
- **prompt** (required): The question or prompt for Claude CLI
- **model** (optional): Model to use (uses CLI default if not specified)
- **fallback_model** (optional): Enable automatic fallback to specified model when default model is overloaded (only works with print mode)
- **print_mode** (optional): Print response and exit (non-interactive mode) - defaults to True for MCP usage
- **output_format** (optional): Output format (uses CLI default if not specified) - only works with print mode
- **input_format** (optional): Input format (uses CLI default if not specified) - only works with print mode
- **permission_mode** (optional): Permission mode (acceptEdits, bypassPermissions, default, plan)
- **allowed_tools** (optional): List of tool names to allow (e.g. 'Bash(git:*)', 'Edit')
- **disallowed_tools** (optional): List of tool names to deny (e.g. 'Bash(git:*)', 'Edit')
- **add_dir** (optional): Additional directories to allow tool access to
- **append_system_prompt** (optional): Append a system prompt to the default system prompt
- **debug** (optional): Enable debug mode
- **verbose** (optional): Enable verbose mode
- **dangerously_skip_permissions** (optional): Bypass all permission checks (recommended only for sandboxes)

## Examples

**Codex:**
```python
# Claude Code will call:
ask_codex(
    prompt="Review this pull request and suggest improvements",
    working_directory="/path/to/project"
)

# Which executes:
# codex exec "Review this pull request and suggest improvements" --cd /path/to/project
```

**GitHub Copilot:**
```python
# Claude Code will call:
ask_copilot(
    prompt="Suggest improvements for this code",
    allow_all_tools=True
)

# Which executes:
# copilot --prompt "Suggest improvements for this code" --allow-all-tools
```

**Claude CLI:**
```python
# Claude Code will call:
ask_claude(
    prompt="Analyze this codebase for potential issues",
    permission_mode="acceptEdits",
    output_format="json"
)

# Which executes:
# claude --print "Analyze this codebase for potential issues" --permission-mode acceptEdits --output-format json
```

## Development

Run the server directly:
```bash
python3 server.py
```

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors and contributors are not responsible for any damage, data loss, security breaches, or other issues that may arise from using this tool. Users assume all responsibility for the actions performed by AI models through this MCP server.

By using this software, you acknowledge that:
- AI models can execute commands and modify files on your system
- You understand the risks associated with giving AI tools system access  
- You will take appropriate precautions to protect your data and systems
- You will not hold the authors liable for any consequences of AI actions

## License

MIT