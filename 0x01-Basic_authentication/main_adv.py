#!/usr/bin/env python3
""" Main Advanced
"""
from api.v1.auth.auth import Auth

# Initialize an instance of Auth
auth = Auth()

# Define some test cases with paths and excluded_paths
test_cases = [
    ("/api/v1/users", ["/api/v1/stat*"]),  # Expect True
    ("/api/v1/status", ["/api/v1/stat*"]),  # Expect False
    ("/api/v1/stats", ["/api/v1/stat*"]),  # Expect False
]

# Iterate over the test cases
for path, excluded_paths in test_cases:
    print(f"Path: {path}, Excluded Paths: {excluded_paths}")
    result = auth.require_auth(path, excluded_paths)
    print(f"Result: {result}")
    print("-" * 20)
