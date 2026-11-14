
import json
from unittest.mock import MagicMock, patch

from backend.llm_agent import (
    check_upgrade,
    find_upgrade,
    run_security_agent,
)


# ==========================================
# TEST 1: CHECK UPGRADE
# ==========================================

def test_check_upgrade():
    fake_result = {
        "status": "VULNERABILITIES_REMAIN",
        "remaining_osv_records": 6,
    }

    with patch(
        "backend.llm_agent.validate_upgrade",
        return_value=fake_result,
    ) as mock_validate:

        result = check_upgrade(
            "requests",
            "2.19.0",
            "2.31.0",
        )

    assert json.loads(result) == fake_result

    mock_validate.assert_called_once_with(
        "requests",
        "2.19.0",
        "2.31.0",
    )


# ==========================================
# TEST 2: FIND UPGRADE
# ==========================================

def test_find_upgrade():
    fake_result = {
        "status": "POTENTIAL_UPGRADE",
        "recommended_candidate": "2.34.2",
    }

    with patch(
        "backend.llm_agent.recommend_upgrade",
        return_value=fake_result,
    ) as mock_recommend:

        result = find_upgrade(
            "requests",
            "2.19.0",
        )

    assert json.loads(result) == fake_result

    mock_recommend.assert_called_once_with(
        "requests",
        "2.19.0",
        python_version="3.13",
        max_candidates=5,
    )


# ==========================================
# TEST 3: AI AGENT CALLS THE CORRECT TOOL
# ==========================================

def test_agent_calls_tool():

    # Simulate Qwen requesting find_upgrade.
    tool_call = MagicMock()
    tool_call.function.name = "find_upgrade"
    tool_call.function.arguments = {
        "package": "requests",
        "current": "2.19.0",
    }

    # First LLM response: request a tool call.
    first_response = MagicMock()
    first_response.message.tool_calls = [tool_call]
    first_response.message.content = ""

    # Second LLM response: return the final answer.
    second_response = MagicMock()
    second_response.message.tool_calls = []
    second_response.message.content = (
        "Potential upgrade identified."
    )

    # Simulated remediation result.
    fake_tool_result = json.dumps({
        "status": "POTENTIAL_UPGRADE",
        "recommended_candidate": "2.34.2",
    })

    mock_find = MagicMock(
        return_value=fake_tool_result
    )

    # Mock Ollama and the registered agent tool.
    with patch(
        "backend.llm_agent.client.chat"
    ) as mock_chat, patch.dict(
        "backend.llm_agent.AVAILABLE_TOOLS",
        {"find_upgrade": mock_find},
    ):

        mock_chat.side_effect = [
            first_response,
            second_response,
        ]

        answer = run_security_agent(
            "Find a potential upgrade for requests 2.19.0."
        )

    # Verify the answer.
    assert answer == "Potential upgrade identified."

    # Verify Qwen was called twice.
    assert mock_chat.call_count == 2

    # Verify the correct remediation tool was called.
    mock_find.assert_called_once_with(
        package="requests",
        current="2.19.0",
    )

    # Verify tool results were passed back to Qwen.
    second_call_messages = mock_chat.call_args_list[1].kwargs["messages"]

    assert any(
        message.get("role") == "tool"
        and message.get("tool_name") == "find_upgrade"
        and message.get("content") == fake_tool_result
        for message in second_call_messages
        if isinstance(message, dict)
    )
