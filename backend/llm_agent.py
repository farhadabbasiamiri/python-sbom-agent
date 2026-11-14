
import json

from ollama import Client
from remediation import validate_upgrade, recommend_upgrade


# ==========================================
# MODEL CONFIGURATION
# ==========================================

MODEL_NAME = "gemma3:4b"
AGENT_MODEL = "qwen3:4b"

client = Client(timeout=120)


# ==========================================
# EXISTING VULNERABILITY EXPLANATION
# ==========================================

def explain_vulnerability(package, version, description):
    response = client.chat(
        model=MODEL_NAME,
        messages=[
            {
                "role": "system",
                "content": (
                    "Explain Python security vulnerabilities "
                    "in simple English. Do not invent CVEs "
                    "or security fixes."
                )
            },
            {
                "role": "user",
                "content": (
                    f"Package: {package}\n"
                    f"Version: {version}\n"
                    f"Description: {description}"
                )
            }
        ]
    )

    return response.message.content or ""


# ==========================================
# REMEDIATION TOOLS
# ==========================================

def check_upgrade(package, current, candidate):
    result = validate_upgrade(
        package,
        current,
        candidate
    )

    return json.dumps(result, default=str)


def find_upgrade(package, current):
    result = recommend_upgrade(
        package,
        current,
        python_version="3.13",
        max_candidates=5
    )

    return json.dumps(result, default=str)


AVAILABLE_TOOLS = {
    "check_upgrade": check_upgrade,
    "find_upgrade": find_upgrade
}


# ==========================================
# EXPLICIT TOOL DEFINITIONS
# ==========================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "find_upgrade",
            "description": (
                "Find a potential Python package upgrade "
                "using PyPI and OSV evidence."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Python package name"
                    },
                    "current": {
                        "type": "string",
                        "description": "Currently installed version"
                    }
                },
                "required": ["package", "current"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_upgrade",
            "description": (
                "Check whether a proposed Python package "
                "version has known OSV findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Python package name"
                    },
                    "current": {
                        "type": "string",
                        "description": "Currently installed version"
                    },
                    "candidate": {
                        "type": "string",
                        "description": "Proposed upgrade version"
                    }
                },
                "required": [
                    "package",
                    "current",
                    "candidate"
                ]
            }
        }
    }
]


# ==========================================
# CLEAN MODEL OUTPUT
# ==========================================

def clean_response(content):
    content = content or ""

    # Remove visible Qwen thinking text.
    if "</think>" in content:
        content = content.split("</think>")[-1]

    # Avoid displaying an unfinished thinking block.
    if "<think>" in content:
        content = content.split("<think>")[0]

    return content.strip()


# ==========================================
# DEBUG HELPER
# ==========================================

def debug_response(response):
    """
    Display Qwen's tool calls and raw response
    in the terminal for troubleshooting.
    """

    print(
        "DEBUG: Tool calls:",
        response.message.tool_calls,
        flush=True
    )

    print(
        "DEBUG: Raw AI response:",
        repr(response.message.content),
        flush=True
    )


# ==========================================
# INTERACTIVE SECURITY AGENT
# ==========================================

def run_security_agent(question):

    if not question or not question.strip():
        return "Please enter a security question."

    messages = [
        {
            "role": "system",
            "content": (
                "You are a Python dependency security agent. "
                "Use available tools when users ask about "
                "package upgrades or known OSV vulnerabilities. "
                "Never invent CVEs, versions, or vulnerability "
                "counts. Use the term 'potential upgrade "
                "candidate', not 'safest upgrade'. "
                "Zero OSV findings do not prove security. "
                "Compatibility must be tested separately. "
                "Do not install or modify packages. "
                "Give a short answer based on tool evidence."
            )
        },
        {
            "role": "user",
            "content": question
        }
    ]

    for round_number in range(3):

        print(
            f"DEBUG: Sending request to Qwen "
            f"(round {round_number + 1})",
            flush=True
        )

        response = client.chat(
            model=AGENT_MODEL,
            messages=messages,
            tools=TOOLS,
            think=False,
            options={
                "temperature": 0,
                "num_predict": 2048,
                "num_ctx": 4096
            }
        )

        print(
            "DEBUG: Qwen responded",
            flush=True
        )

        # NEW: Show whether Qwen requested any tools.
        debug_response(response)

        messages.append(response.message)

        tool_calls = response.message.tool_calls or []

        # ------------------------------------------
        # NO TOOL CALL
        # ------------------------------------------

        if not tool_calls:

            answer = clean_response(
                response.message.content
            )

            if not answer or (
                "Okay, the user" in answer
                and "I should" in answer
            ):
                print(
                    "DEBUG: Qwen returned no usable final answer",
                    flush=True
                )

                return (
                    "Qwen did not produce a complete security "
                    "answer. Check the terminal debug output."
                )

            print(
                "DEBUG: Returning final answer",
                flush=True
            )

            return answer

        # ------------------------------------------
        # EXECUTE TOOLS REQUESTED BY QWEN
        # ------------------------------------------

        for call in tool_calls:

            tool_name = call.function.name
            arguments = call.function.arguments or {}

            print(
                f"DEBUG: AI requested {tool_name}",
                flush=True
            )

            print(
                "DEBUG: Tool arguments:",
                arguments,
                flush=True
            )

            if tool_name not in AVAILABLE_TOOLS:

                result = json.dumps({
                    "error": "Unknown tool requested"
                })

            else:
                try:
                    print(
                        f"DEBUG: Starting {tool_name}",
                        flush=True
                    )

                    result = AVAILABLE_TOOLS[tool_name](
                        **arguments
                    )

                    print(
                        f"DEBUG: {tool_name} finished",
                        flush=True
                    )

                except Exception as error:

                    print(
                        f"DEBUG: Tool error: {error}",
                        flush=True
                    )

                    result = json.dumps({
                        "error": (
                            f"{type(error).__name__}: {error}"
                        )
                    })

            messages.append({
                "role": "tool",
                "tool_name": tool_name,
                "content": result
            })

    # ==========================================
    # FINAL RESPONSE AFTER TOOL-CALL LIMIT
    # ==========================================

    print(
        "DEBUG: Requesting final Qwen answer",
        flush=True
    )

    response = client.chat(
        model=AGENT_MODEL,
        messages=messages,
        think=False,
        options={
               "temperature": 0,
    "num_predict": 2048,
    "num_ctx": 4096
        }
    )

    print(
        "DEBUG: Final Qwen response received",
        flush=True
    )

    debug_response(response)

    answer = clean_response(
        response.message.content
    )

    return answer or "Analysis incomplete."


# ==========================================
# DIRECT TEST
# ==========================================

if __name__ == "__main__":

    print(
        "Testing security agent...",
        flush=True
    )

    result = run_security_agent(
        "Find a potential upgrade for requests 2.19.0."
    )

    print("\nAGENT ANSWER:\n")
    print(result)
