# SafeSpace Shield

### Think Before You Click. Understand Before You Trust.

SafeSpace Shield is a cybersecurity awareness application that analyzes potentially suspicious messages, identifies common phishing indicators, explains possible risks, and provides practical safety recommendations.

## Problem

People frequently receive suspicious messages pretending to be from banks, delivery services, government organizations, and other trusted sources. These messages may use urgency, impersonation, or suspicious links to trick recipients into revealing sensitive information.

## Solution

SafeSpace Shield helps users recognize potential warning signs in suspicious messages through a simple, accessible interface. It analyzes message content, assigns a heuristic risk level, explains detected indicators, and suggests safer actions.

## Features

- Analyze pasted text messages (up to 5,000 characters).
- Detect suspicious keywords and phrases.
- Identify selected suspicious URL patterns.
- Detect valid IP-address-based URLs.
- Classify messages into Low, Medium, and High risk levels.
- Display a risk score and detection metrics.
- Explain why a message may be suspicious.
- Provide risk-based safety recommendations.
- Include sample messages for High, Medium, and Low risk demonstrations.
- Support Light Mode and Dark Mode.
- Support keyboard-based form submission using Ctrl+Enter.
- Process messages locally without requiring a paid external API.

## Technology Stack

- Python 3.13
- Streamlit
- Regular Expressions (Regex)
- Python `ipaddress` and `urllib.parse` modules
- Git and GitHub

## Run Locally

1. Clone this repository.
2. Open the project folder in a terminal.
3. Create a virtual environment:

   ```bash
   py -3.13 -m venv .venv
   ```

4. Activate it on Windows PowerShell:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

5. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

6. Start the application:

   ```bash
   python -m streamlit run app.py
   ```

7. Open the local URL displayed in your terminal.

## Run the Detection Tests

Run the test suite using:

```bash
python test_analyzer.py
```

The tests cover:

- Suspicious keyword detection.
- URL pattern detection and extraction.
- IP-based URL detection.
- False-positive handling.
- Risk scoring.
- Educational-context handling.
- Threat explanations and safety recommendations.
- Empty, whitespace-only, and long-message inputs.

## Privacy

Messages are processed locally by the application. The current version does not require users to create accounts or submit messages to a paid external API.

## Important Limitations

- Detection relies on predefined keywords, URL patterns, and heuristic rules.
- Risk scores are indicators, not probabilities of malicious activity.
- A Low Risk result does not guarantee that a message is safe.
- The application does not verify the reputation or actual maliciousness of a website.
- Detection results should be treated as cybersecurity guidance, not a substitute for professional security tools.

Always verify suspicious requests through official communication channels.

## Project Category

Cybersecurity | Online Safety | Scam Awareness

---

**SafeSpace Shield — Think Before You Click. Understand Before You Trust.**