
from ollama import chat

MODEL_NAME = "gemma3:4b"


def explain_vulnerability(package, version, description):
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


if __name__ == "__main__":
    result = explain_vulnerability(
        "Django",
        "2.2.0",
        "SQL Injection vulnerability"
    )

    print(result)
