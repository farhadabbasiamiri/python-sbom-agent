
import json

from ollama import chat
from remediation import validate_upgrade, recommend_upgrade


# ==================================================
# PART 1: EXISTING LLM EXPLANATION
# ==================================================

MODEL_NAME = "gemma3:4b"
AGENT_MODEL = "qwen3:4b"


def explain_vulnerability(package, version, description):
    """
    Explain a vulnerability using the local Gemma model.
    """

    response = chat(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity assistant. "
                    "Explain vulnerabilities in simple English. "
                    "Do not invent CVEs or security fixes."
                )
            },
            {
                "role": "user",
                "content": (
                    f"Package: {package}\n"
                    f"Version: {version}\n"
                    f"Vulnerability: {description}\n"
                    "Explain the security risk and suggest "
                    "safe next steps in 3 sentences."
                )
            }
        ]
    )

    return response.message.content


# ==================================================
# PART 2: NEW AGENTIC TOOLS
# ==================================================

def check_upgrade(
    package: str,
    current: str,
    candidate: str
) -> str:
    """
    Check whether a proposed upgrade still has known
    OSV vulnerabilities.

    Args:
        package: Python package name.
        current: Installed package version.
        candidate: Proposed upgrade version.
    """

    result = validate_upgrade(
        package,
        current,
        candidate
    )

    return json.dumps(result)


def find_upgrade(package: str, current: str) -> str:
    """
    Automatically find a potential upgrade using
    PyPI and OSV.

    Args:
        package: Python package name.
        current: Installed package version.
    """

    result = recommend_upgrade(
        package,
        current,
        python_version="3.13",
        max_candidates=5
    )

    return json.dumps(result)


# ==================================================
# PART 3: NEW LLM-POWERED AGENT
# ==================================================

def run_security_agent(question: str) -> str:
    """
    Let the local LLM select and execute
    security investigation tools.

    No packages are installed or modified.
    """

    available_tools = {
        "check_upgrade": check_upgrade,
        "find_upgrade": find_upgrade
    }

    messages = [
    {
        "role": "system",
        "content": (
            "You are an evidence-based Python dependency security agent. "
            "Use available tools to verify package upgrade candidates. "
            "Base all vulnerability counts, versions, and recommendations "
            "strictly on tool results. "
            "Never invent CVEs, fixes, or vulnerability counts. "
            "Always say 'potential upgrade candidate', never 'safest upgrade'. "
            "If OSV returns zero records, say 'no known OSV findings', "
            "not 'completely secure' or 'all vulnerabilities resolved'. "
            "OSV records may overlap, so do not call them unique vulnerabilities. "
            "Do not claim other versions were checked unless tool results prove it. "
            "Always mention that application compatibility requires testing. "
            "Never install or modify packages. "
            "Explain results in simple English."
        )
    },
    {
        "role": "user",
        "content": question
    }
]

    # Allow up to three rounds of tool calls.
    for _ in range(3):

        response = chat(
            model=AGENT_MODEL,
            messages=messages,
            tools=list(available_tools.values())
        )

        messages.append(response.message)

        if not response.message.tool_calls:
            return (
                response.message.content
                or "No answer generated."
            )

        for call in response.message.tool_calls:

            tool_name = call.function.name
            arguments = call.function.arguments

            if tool_name not in available_tools:
                result = json.dumps({
                    "error": "Unknown tool requested."
                })

            else:
                try:
                    print(f"AI calling tool: {tool_name}")

                    result = available_tools[tool_name](
                        **arguments
                    )

                except Exception as error:
                    result = json.dumps({
                        "error": (
                            f"Tool execution failed: "
                            f"{type(error).__name__}"
                        )
                    })

            messages.append({
                "role": "tool",
                "tool_name": tool_name,
                "content": result
            })

    # Give the model a final response using the
    # evidence gathered during the tool calls.
    response = chat(
        model=AGENT_MODEL,
        messages=messages
    )

    return (
        response.message.content
        or "Analysis incomplete."
    )


# ==================================================
# PART 4: ORIGINAL TEST
# ==================================================

if __name__ == "__main__":

    result = explain_vulnerability(
        "Django",
        "2.2.0",
        "SQL Injection vulnerability"
    )

    print(result)
