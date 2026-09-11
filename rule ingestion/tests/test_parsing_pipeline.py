import os
import sys
import pytest

# Configure python path to root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.services.sigma_parser import parse_sigma_rule, SigmaParseError, _extract_mitre_techniques
from app.services.kql_parser import parse_kql_rule, KqlParseError

def test_parse_sigma_rule_success():
    yaml_content = """
title: Suspicious Process Execution
id: 12345678-1234-1234-1234-123456789abc
description: Detects suspicious cmd.exe execution
author: Test Author
status: experimental
tags:
  - attack.t1059.001
  - attack.execution
detection:
  selection:
    CommandLine|contains: 'cmd.exe'
  condition: selection
"""
    result = parse_sigma_rule(yaml_content)
    assert result["title"] == "Suspicious Process Execution"
    assert result["rule_id"] == "12345678-1234-1234-1234-123456789abc"
    assert result["mitre_techniques"] == ["T1059.001"]
    assert result["is_active"] is True

def test_parse_sigma_rule_deprecated_status():
    yaml_content = """
title: Deprecated Rule
id: 87654321-4321-4321-4321-cba987654321
status: deprecated
detection:
  selection:
    CommandLine|contains: 'powershell'
  condition: selection
"""
    result = parse_sigma_rule(yaml_content)
    assert result["is_active"] is False

def test_parse_sigma_rule_invalid_yaml():
    invalid_yaml = "title: Malformed:\n  - incomplete: [yaml"
    with pytest.raises(SigmaParseError):
        parse_sigma_rule(invalid_yaml)

def test_parse_sigma_rule_missing_fields():
    missing_detection = "title: Test Rule without detection"
    with pytest.raises(SigmaParseError) as exc_info:
        parse_sigma_rule(missing_detection)
    assert "detection" in str(exc_info.value)

def test_parse_kql_rule_success():
    kql_content = "// Title: KQL Process Check\n// Author: Security Team\nSecurityEvent | where EventID == 4688"
    result = parse_kql_rule(kql_content)
    assert result["title"] == "KQL Process Check"
    assert "SecurityEvent" in result["detection_logic"]

def test_parse_kql_rule_empty():
    with pytest.raises(KqlParseError):
        parse_kql_rule("   \n  ")

def test_mitre_technique_extraction():
    tags = ["attack.t1059.001", "attack.t1105", "custom.tag", "attack.t1486"]
    techniques = _extract_mitre_techniques(tags)
    assert techniques == ["T1059.001", "T1105", "T1486"]
