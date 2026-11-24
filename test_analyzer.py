
from analyzer import (
    detect_suspicious_keywords,
    detect_suspicious_url_patterns,
    detect_ip_based_urls,
    calculate_risk,
    generate_explanation
)

test_message = """
URGENT! Your bank account is blocked.
Verify your account immediately.
Visit http://bank-verify.example.com to restore access.
"""

keyword_results = detect_suspicious_keywords(test_message)
url_results = detect_suspicious_url_patterns(test_message)
risk_results = calculate_risk(test_message)
explanation_results = generate_explanation(test_message)

print("SAFE SPACE SHIELD - ANALYSIS REPORT")
print("-----------------------------------")

print("\nSuspicious Keywords:", keyword_results)
print("Suspicious URL Patterns:", url_results)

print("\nRisk Score:", risk_results["score"])
print("Risk Level:", risk_results["risk_level"])

print("\nWHY IS THIS MESSAGE SUSPICIOUS?")

for reason in explanation_results["reasons"]:
    print("-", reason)

print("\nSAFETY RECOMMENDATIONS")

for recommendation in explanation_results["recommendations"]:
    print("-", recommendation)

print("\nIP-BASED URL DETECTION TESTS")
print("----------------------------")

# Test 1: Valid IP-based URL
test1 = detect_ip_based_urls(
    "Visit http://192.168.1.10/login"
)
assert len(test1) == 1
print("Test 1 passed: Valid IP URL detected.")

# Test 2: Normal domain
test2 = detect_ip_based_urls(
    "Visit https://google.com/login"
)
assert len(test2) == 0
print("Test 2 passed: Normal domain not flagged.")

# Test 3: Invalid IP address
test3 = detect_ip_based_urls(
    "Visit http://256.300.1.5/login"
)
assert len(test3) == 0
print("Test 3 passed: Invalid IP rejected.")

print("\nAll IP detection tests passed!")

print("\nADDITIONAL URL PATTERN TESTS")
print("----------------------------")

new_patterns = [
    "account-suspended",
    "verify-identity",
    "password-reset",
    "secure-login",
    "update-payment",
    "free-gift"
]

for pattern in new_patterns:
    result = detect_suspicious_url_patterns(
        f"Visit https://{pattern}.example.com/login"
    )

    assert pattern in result
    print(f"Passed: {pattern}")

print("\nURL EXTRACTION EDGE CASE TESTS")
print("--------------------------------")

# Test 1: URL inside brackets
assert detect_suspicious_url_patterns(
    "(https://bank-verify.example.com/login)."
) == ["bank-verify"]
print("Test 1 passed: URL inside brackets.")

# Test 2: Trailing punctuation
assert detect_suspicious_url_patterns(
    "https://bank-verify.example.com/login, today."
) == ["bank-verify"]
print("Test 2 passed: Trailing punctuation.")

# Test 3: www URL
assert detect_suspicious_url_patterns(
    "www.bank-verify.example.com/login"
) == ["bank-verify"]
print("Test 3 passed: www URL.")

# Test 4: Bare domain
assert detect_suspicious_url_patterns(
    "bank-verify.example.com/login"
) == ["bank-verify"]
print("Test 4 passed: Bare domain.")

# Test 5: URL with port
assert detect_suspicious_url_patterns(
    "https://bank-verify.example.com:8080/login"
) == ["bank-verify"]
print("Test 5 passed: URL with port.")

# Test 6: URL with fragment
assert detect_suspicious_url_patterns(
    "https://bank-verify.example.com/login#verify"
) == ["bank-verify"]
print("Test 6 passed: URL with fragment.")

# Test 7: Ordinary bare domain
assert detect_suspicious_url_patterns(
    "Visit example.com for information."
) == []
print("Test 7 passed: Ordinary bare domain.")

# Test 8: Email address
assert detect_suspicious_url_patterns(
    "Contact support@bank-verify.example.com"
) == []
print("Test 8 passed: Email address is not treated as a URL.")

print("All 8 URL extraction edge case tests passed!")

print("\nFALSE POSITIVE TESTS")
print("--------------------")

assert detect_suspicious_url_patterns(
    "I received a free-gift from my friend."
) == []

assert detect_suspicious_url_patterns(
    "The words secure-login appeared in our meeting notes."
) == []

assert detect_suspicious_url_patterns(
    "Visit https://google.com for information."
) == []

print("All 3 false-positive tests passed!")


print("\nRISK SCORING TESTS")
print("------------------")

# Test 1: IP URL and suspicious pattern should not be double-counted.
result = calculate_risk(
    "Visit http://192.168.1.10/bank-verify/login"
)

assert result["score"] == 2, (
    f"Expected score 2, but got {result['score']}. "
    f"Full result: {result}"
)
print("Test 1 passed: No double-counting.")

# Test 2: IP URL without suspicious pattern.
result = calculate_risk(
    "Visit http://192.168.1.10/login"
)
assert result["score"] == 2, (
    f"Expected score 2, but got {result['score']}. "
    f"Full result: {result}"
)
print("Test 2 passed: IP-only scoring.")

# Test 3: Suspicious pattern without IP address.
result = calculate_risk(
    "Visit https://bank-verify.example.com/login"
)
assert result["score"] == 2, (
    f"Expected score 2, but got {result['score']}. "
    f"Full result: {result}"
)
print("Test 3 passed: Suspicious-pattern scoring.")

print("All 3 risk scoring tests passed!")

print("\nEDUCATIONAL CONTEXT RISK SCORING TESTS")
print("--------------------------------------")

# Test 1: Harmless cybersecurity training
result = calculate_risk(
    "Our cybersecurity training explains that your computer is infected and teaches employees to contact Microsoft support."
)

assert result["score"] == 0
assert result["risk_level"] == "Low"

print("Test 1 passed: Harmless cybersecurity training scores Low.")

# Test 2: Harmless IT training
result = calculate_risk(
    "Our IT training explains why employees should grant remote access only when authorized."
)

assert result["score"] == 0
assert result["risk_level"] == "Low"

print("Test 2 passed: Harmless IT training scores Low.")

# Test 3: Genuine Microsoft support scam
result = calculate_risk(
    "Your computer is infected! Call Microsoft support immediately."
)

assert result["score"] == 3
assert result["risk_level"] == "Medium"

print("Test 3 passed: Microsoft support scam retains its risk score.")

# Test 4: Genuine remote access scam
result = calculate_risk(
    "Grant remote access now and install remote access software."
)

assert result["score"] == 2
assert result["risk_level"] == "Medium"

print("Test 4 passed: Remote access scam retains its risk score.")

# Test 5: Educational wording with dangerous instructions
result = calculate_risk(
    "This cybersecurity training explains that your computer is infected. Call Microsoft support immediately."
)

assert result["score"] == 3
assert result["risk_level"] == "Medium"

print("Test 5 passed: Dangerous instructions retain their risk score.")

# Test 6: Harmless security awareness message
result = calculate_risk(
    "Hello, this is a security awareness message. "
    "Never share your passwords or OTPs with anyone."
)

assert result["score"] == 0
assert result["risk_level"] == "Low"

print("Test 6 passed: Harmless security awareness message scores Low.")


# Test 7: Educational wording must not hide an OTP scam
result = calculate_risk(
    "This security awareness message explains online safety. "
    "Your bank account is blocked. "
    "Share your OTP immediately to restore access."
)

assert result["score"] >= 5
assert result["risk_level"] == "High"

print("Test 7 passed: Educational wording does not hide an OTP scam.")

print("All 7 educational context risk tests passed!")

print("\nEXPLANATION TESTS")
print("-----------------")

# Test 1: Suspicious message explanation.
result = generate_explanation(
    "URGENT! Your account is blocked. Verify your account immediately using https://bank-verify.example.com/login"
)

assert any("urgency" in reason for reason in result["reasons"])
assert any("account is blocked" in reason for reason in result["reasons"])
assert any("suspicious URL" in reason for reason in result["reasons"])

print("Test 1 passed: Threat explanations.")

# Test 2: Sensitive information warning.
result = generate_explanation(
    "Your OTP and password are required. Please provide your bank details immediately."
)

assert any("OTP" in reason for reason in result["reasons"])
assert any("login credentials" in reason for reason in result["reasons"])
assert any("banking information" in reason for reason in result["reasons"])

assert any("Never share OTPs" in recommendation for recommendation in result["recommendations"])

print("Test 2 passed: Sensitive information warnings.")

# Test 3: Ordinary message.
result = generate_explanation(
    "Hello! Hope you are having a wonderful day."
)

assert len(result["reasons"]) == 1
assert "No suspicious indicators" in result["reasons"][0]

print("Test 3 passed: Ordinary message.")

print("All 3 explanation tests passed!")

print("\nACCOUNT SUSPENSION TESTS")
print("------------------------")

messages = [
    "Your account has been suspended.",
    "Your account is suspended.",
    "Your account access will be suspended."
]

expected_keywords = [
    "account has been suspended",
    "account is suspended",
    "account access will be suspended"
]

for message, expected in zip(messages, expected_keywords):
    result = detect_suspicious_keywords(message)

    assert expected in result

    print(f"Passed: {expected}")

print("All 3 account suspension tests passed!")

print("\nACCOUNT SUSPENSION EXPLANATION TEST")
print("-----------------------------------")

message = """
Your account has been suspended.
Restore access immediately:
https://account-suspended.example.com/login
"""

result = generate_explanation(message)

assert (
    "The message claims that an account has been suspended or will be suspended."
    in result["reasons"]
)

assert (
    "Verify account suspension claims directly through the organization's official website."
    in result["recommendations"]
)

print("Account suspension explanation test passed!")

print("\nDELIVERY SCAM KEYWORD TESTS")
print("---------------------------")

messages = [
    "Your package is on hold.",
    "Please pay the delivery fee.",
    "A redelivery fee is required."
]

expected_keywords = [
    "package is on hold",
    "pay the delivery fee",
    "redelivery fee"
]

for message, expected in zip(messages, expected_keywords):
    result = detect_suspicious_keywords(message)

    assert expected in result

    print(f"Passed: {expected}")

print("All 3 delivery scam tests passed!")

print("\nDELIVERY URL PATTERN TEST")
print("-------------------------")

message = "Visit https://delivery-update.example.com/pay"

result = detect_suspicious_url_patterns(message)

assert "delivery-update" in result

print("Delivery URL pattern test passed!")

print("\nPAYMENT SCAM KEYWORD TESTS")
print("--------------------------")

messages = [
    "You must pay a processing fee.",
    "Click here to release your payment.",
    "Your payment will be cancelled."
]

expected_keywords = [
    "pay a processing fee",
    "release your payment",
    "payment will be cancelled"
]

for message, expected in zip(messages, expected_keywords):
    result = detect_suspicious_keywords(message)

    assert expected in result

    print(f"Passed: {expected}")

print("All 3 payment scam tests passed!")

print("\nPAYMENT URL PATTERN TEST")
print("------------------------")

message = "Visit https://payment-release.example.com/verify"

result = detect_suspicious_url_patterns(message)

assert "payment-release" in result

print("Payment URL pattern test passed!")

print("\nIMPERSONATION KEYWORD TESTS")
print("---------------------------")

messages = [
    "We are from your bank.",
    "Contact the bank security department.",
    "Government verification required."
]

expected_keywords = [
    "we are from your bank",
    "bank security department",
    "government verification required"
]

for message, expected in zip(messages, expected_keywords):
    result = detect_suspicious_keywords(message)

    assert expected in result

    print(f"Passed: {expected}")

print("All 3 impersonation tests passed!")

print("\nBANK AND GOVERNMENT IMPERSONATION EXPLANATION TESTS")
print("---------------------------------------------------")

message = (
    "We are from your bank. "
    "Contact the bank security department. "
    "Immediate government verification required."
)

result = generate_explanation(message)

assert any(
    "impersonating a bank" in reason
    for reason in result["reasons"]
)

assert any(
    "government verification claims" in reason
    for reason in result["reasons"]
)

assert any(
    "Contact your bank" in recommendation
    for recommendation in result["recommendations"]
)

assert any(
    "government website" in recommendation
    for recommendation in result["recommendations"]
)

print("Bank impersonation explanation passed!")
print("Government verification explanation passed!")
print("Bank safety recommendation passed!")
print("Government safety recommendation passed!")

print("All impersonation explanation tests passed!")

print("\nTECHNICAL SUPPORT SCAM KEYWORD TESTS")
print("------------------------------------")

messages = [
    "Your computer is infected.",
    "Your device is infected.",
    "Virus detected.",
    "Call technical support.",
    "Contact technical support.",
    "Grant remote access.",
    "Install remote access software.",
    "Remote access required.",
    "Microsoft support."
]

expected_keywords = [
    "your computer is infected",
    "your device is infected",
    "virus detected",
    "call technical support",
    "contact technical support",
    "grant remote access",
    "install remote access software",
    "remote access required",
    "microsoft support"
]

for message, expected in zip(messages, expected_keywords):
    result = detect_suspicious_keywords(message)

    assert expected in result

    print(f"Passed: {expected}")

print("All 9 technical support tests passed!")

print("\nTECHNICAL SUPPORT EXPLANATION TESTS")
print("-----------------------------------")

test_cases = [
    {
        "message": "Your computer is infected. Virus detected.",
        "expected": "fake virus or infection alert"
    },
    {
        "message": "Grant remote access. Install remote access software.",
        "expected": "remote access to your device"
    },
    {
        "message": "Microsoft support.",
        "expected": "impersonating Microsoft technical support"
    }
]

for test in test_cases:
    result = generate_explanation(test["message"])

    assert any(
        test["expected"] in reason
        for reason in result["reasons"]
    )

    assert len(result["recommendations"]) > 0

    print(f"Passed: {test['expected']}")

print("All 3 technical support explanation tests passed!")

print("\nEDUCATIONAL CONTEXT EXPLANATION TESTS")
print("-------------------------------------")

# Test 1: Harmless cybersecurity training
result = generate_explanation(
    "Our cybersecurity training explains that your computer is infected and teaches employees to contact Microsoft support."
)

assert not any(
    "fake virus" in reason or "impersonating Microsoft" in reason
    for reason in result["reasons"]
)

print("Test 1 passed: Harmless cybersecurity training.")

# Test 2: Harmless IT education
result = generate_explanation(
    "Our IT training explains why employees should grant remote access only when authorized."
)

assert not any(
    "remote access to your device" in reason
    for reason in result["reasons"]
)

print("Test 2 passed: Harmless IT education.")

# Test 3: Genuine Microsoft support scam
result = generate_explanation(
    "Your computer is infected! Call Microsoft support immediately."
)

assert any(
    "fake virus" in reason
    for reason in result["reasons"]
)

assert any(
    "impersonating Microsoft" in reason
    for reason in result["reasons"]
)

print("Test 3 passed: Microsoft support scam warning.")

# Test 4: Genuine remote access scam
result = generate_explanation(
    "Grant remote access now and install remote access software."
)

assert any(
    "remote access to your device" in reason
    for reason in result["reasons"]
)

print("Test 4 passed: Remote access scam warning.")

# Test 5: Educational wording with dangerous instructions
result = generate_explanation(
    "This cybersecurity training explains that your computer is infected. Call Microsoft support immediately."
)

assert any(
    "fake virus" in reason
    for reason in result["reasons"]
)

assert any(
    "impersonating Microsoft" in reason
    for reason in result["reasons"]
)

print("Test 5 passed: Dangerous instructions are not hidden by educational wording.")

print("All 5 educational context tests passed!")

# Test 1: Low-risk recommendations
result = generate_explanation("Hello, have a nice day.")
assert "Remain cautious when interacting with unexpected messages." in result["recommendations"]
assert "Check links and sender details before taking action." in result["recommendations"]
assert "Report the suspicious message." not in result["recommendations"]

print("Test 1 passed: Low-risk recommendations.")

# Test 2: Medium-risk recommendations
result = generate_explanation("Please verify your account immediately.")
assert "Check the sender's identity carefully." in result["recommendations"]
assert "Verify important claims through official channels." in result["recommendations"]
assert "Report the suspicious message." not in result["recommendations"]

print("Test 2 passed: Medium-risk recommendations.")

# Test 3: High-risk recommendations
message = (
    "URGENT! Your account is blocked. "
    "Verify your account immediately at "
    "https://bank-verify.example.com/login"
)
result = generate_explanation(message)

assert "Contact the organization through its official website or phone number." in result["recommendations"]
assert "Report the suspicious message." in result["recommendations"]
assert "Remain cautious when interacting with unexpected messages." not in result["recommendations"]
assert "Check links and sender details before taking action." not in result["recommendations"]

print("Test 3 passed: High-risk recommendations.")


print("\nINPUT ROBUSTNESS TESTS")
print("----------------------")

# Test 1: Empty message
message = ""

assert detect_suspicious_keywords(message) == []
assert detect_suspicious_url_patterns(message) == []
assert detect_ip_based_urls(message) == []

result = calculate_risk(message)
assert result["score"] == 0
assert result["risk_level"] == "Low"

print("Test 1 passed: Empty message.")

# Test 2: Whitespace-only message
message = "     \n\t     "

assert detect_suspicious_keywords(message) == []
assert detect_suspicious_url_patterns(message) == []
assert detect_ip_based_urls(message) == []

result = calculate_risk(message)
assert result["score"] == 0
assert result["risk_level"] == "Low"

print("Test 2 passed: Whitespace-only message.")

# Test 3: Long harmless message (5000 characters)
message = ("Hello, have a wonderful day! " * 200)[:5000]

assert len(message) == 5000
assert detect_suspicious_keywords(message) == []
assert detect_suspicious_url_patterns(message) == []
assert detect_ip_based_urls(message) == []

result = calculate_risk(message)
assert result["score"] == 0
assert result["risk_level"] == "Low"

print("Test 3 passed: 5000-character harmless message.")

print("All input robustness tests passed!")

# Overlapping keyword detection test

message = "Government verification required"

results = detect_suspicious_keywords(message)

assert results == ["government verification required"]

print("Overlapping keyword test passed!")

# Word boundary regression test

message = "This is an urgentmatter"

results = detect_suspicious_keywords(message)

assert "urgent" not in results

print("Word boundary test passed!")