# import section
from json import load
from claude_agent_sdk import (
    ClaudeSDKClient, 
    ThinkingBlock,
    ClaudeAgentOptions, 
    AssistantMessage, 
    TextBlock, 
)
from loguru import logger
from dotenv import load_dotenv
import os
import asyncio

load_dotenv()

APPROVED_TOOLS=[
    "Read", 
    "Grep", 
    "Bash", 
    "KillShell", 
    "BashOutput", 
    "Fetch", 
    "WebSearch", 
    "ExitPlanMode", 
    "SlashCommand", 
    "WebFetch",
    "Task", 
    "Glob", 
    "Grep", 
    "TodoWrite",
    "Skill",
    "MultiEdit"
]


async def audit_the_kube():
    #system prompt
    instructions = """
    You are an experienced security expert tasked with performing a detailed security audit of a kubernetes cluster.
    You have access to kubeconfig in the user's HOME directory and you have kubectl already installed in the machine. 
    Use the 'k8s-security-audit' skill to identify all the necessary steps
    Then plan and execute the kubernetes security audit as specified in the skill.
    Use the 'memory' mcp server to keep track of TODOs and track the state of the project as the TODOs get completed. 
    You have to do a comprehensive and thorough audit of the cluster and its resources. Don't spare an inch!
    Once done, create a detailed security audit report in markdown format in the current working directory. Nowhere else!
    """
    # user prompt section
    async def perform_kubernetes_audit():
        yield {
            "type": "user",
            "message": {
                "role": "user",
                "content": "Perform a comprehensive and thorough security audit of the cluster and its resources. Don't spare an inch!"
            }
        }

    options = ClaudeAgentOptions(
        max_turns = 10000,
        permission_mode="bypassPermissions",
        system_prompt=instructions,
        setting_sources=["project"],
        allowed_tools = APPROVED_TOOLS,
        mcp_servers={
            "memory": {
                "command": "npx",
                "args": [
                    "-y",
                    "@modelcontextprotocol/server-memory"
                ]
            },
        },
        
        cwd = os.getcwd(),
    )

    async with ClaudeSDKClient(options) as client:
        await client.query(perform_kubernetes_audit())

        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        logger.info(block.text)
                    if isinstance(block, ThinkingBlock):
                        logger.info(block.thinking)


if __name__ == "__main__":
    asyncio.run(audit_the_kube())