
from unittest.mock import patch, MagicMock

from backend.llm_agent import check_upgrade, find_upgrade, run_security_agent


def test_check_upgrade():
    with patch("backend.llm_agent.validate_upgrade") as mock:
        mock.return_value = {
            "status": "VULNERABILITIES_REMAIN",
            "remaining_osv_records": 6
        }

        result = check_upgrade("requests", "2.19.0", "2.31.0")

        assert "VULNERABILITIES_REMAIN" in result
        mock.assert_called_once_with(
            "requests", "2.19.0", "2.31.0"
        )


def test_find_upgrade():
    with patch("backend.llm_agent.recommend_upgrade") as mock:
        mock.return_value = {
            "status": "POTENTIAL_UPGRADE",
            "recommended_candidate": "2.34.2"
        }

        result = find_upgrade("requests", "2.19.0")

        assert "POTENTIAL_UPGRADE" in result
        mock.assert_called_once_with(
            "requests", "2.19.0",
            python_version="3.13",
            max_candidates=5
        )


def test_agent_calls_tool():
    tool_call = MagicMock()
    tool_call.function.name = "find_upgrade"
    tool_call.function.arguments = {
        "package": "requests",
        "current": "2.19.0"
    }

    first_response = MagicMock()
    first_response.message.tool_calls = [tool_call]

    second_response = MagicMock()
    second_response.message.tool_calls = []
    second_response.message.content = "Potential upgrade identified."

    with patch("backend.llm_agent.chat") as mock_chat, \
         patch("backend.llm_agent.find_upgrade") as mock_find:

        mock_chat.side_effect = [
            first_response, second_response
        ]

        mock_find.return_value = '{"status": "POTENTIAL_UPGRADE"}'

        result = run_security_agent(
            "Find an upgrade for requests 2.19.0"
        )

        assert result == "Potential upgrade identified."
        mock_find.assert_called_once()
