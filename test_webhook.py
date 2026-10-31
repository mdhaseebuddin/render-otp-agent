#!/usr/bin/env python3
"""
Unit Test Suite for VeloTest OTP Parser & Deduplication
=======================================================
Verifies that all known and possible VeloTest log formats accurately
extract both the target candidate's email and the OTP code.
"""

import sys
from app import parse_log_for_email_and_otp, is_duplicate

VELOTEST_CASES = [
    # 1. Standard format
    (
        "OTP sent to student@velotest.com: 593821",
        "student@velotest.com",
        "593821"
    ),
    # 2. VeloTest bracketed log
    (
        "[VeloTest] Candidate candidate@exam.org verification code generated: 849201",
        "candidate@exam.org",
        "849201"
    ),
    # 3. OTP then email
    (
        "Sent OTP 123456 to test.user@gmail.com successfully",
        "test.user@gmail.com",
        "123456"
    ),
    # 4. JSON formatted log output
    (
        '{"service": "velotest", "action": "otp_dispatch", "email": "alice@velotest.io", "otp": "993821"}',
        "alice@velotest.io",
        "993821"
    ),
    # 5. Alternate JSON keys
    (
        '{"user": "student_99@college.edu", "verificationCode": "443210"}',
        "student_99@college.edu",
        "443210"
    ),
    # 6. Key-Value structured format
    (
        "VeloTest Auth | email: exam_taker@test.net | code: 771234",
        "exam_taker@test.net",
        "771234"
    ),
    # 7. Colon format
    (
        "OTP for applicant@velotest.com: 654321",
        "applicant@velotest.com",
        "654321"
    ),
    # 8. Unrelated logs (should return None)
    (
        "VeloTest exam session 482910 started for test room 4",
        None,
        None
    ),
    (
        "Database pool connected to postgres://...",
        None,
        None
    )
]

def run_tests():
    print("==================================================")
    print(" Running Unit Tests for VeloTest Log Parsing      ")
    print("==================================================")

    passed = 0
    failed = 0

    for idx, (log_msg, expected_email, expected_otp) in enumerate(VELOTEST_CASES, start=1):
        result = parse_log_for_email_and_otp(log_msg)
        if expected_email is None:
            if result is None:
                print(f"[PASS] Case {idx}: Correctly ignored non-OTP log.")
                passed += 1
            else:
                print(f"[FAIL] Case {idx}: Expected None, got {result} for '{log_msg}'")
                failed += 1
        else:
            if result is not None and result[0].lower() == expected_email.lower() and result[1] == expected_otp:
                print(f"[PASS] Case {idx}: Extracted {result[0]} -> {result[1]}")
                passed += 1
            else:
                print(f"[FAIL] Case {idx}: Expected ({expected_email}, {expected_otp}), got {result}")
                failed += 1

    print("\n--------------------------------------------------")
    print(" Testing Deduplication Logic                      ")
    print("--------------------------------------------------")
    d1 = is_duplicate("candidate@velotest.com", "999888")
    d2 = is_duplicate("candidate@velotest.com", "999888")
    d3 = is_duplicate("candidate@velotest.com", "111222")

    if not d1 and d2 and not d3:
        print("[PASS] Deduplication logic verified successfully.")
        passed += 1
    else:
        print(f"[FAIL] Deduplication mismatch: d1={d1}, d2={d2}, d3={d3}")
        failed += 1

    print("==================================================")
    print(f" Test Summary: {passed} PASSED, {failed} FAILED")
    print("==================================================")

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
