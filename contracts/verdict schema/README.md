# Verdict Schema
 
## Purpose
This schema defines the standard format used by the Validation Engine to publish verdicts after validating detection rules.
 
## Fields
 
| Field                  | Type           | Description                                           |
|------------------------|----------------|-------------------------------------------------------|
| action_id              | string         | Unique identifier of the simulated attack action       |
| verdict                | string         | Detection result (Detected, Missed, Partial, NoData)   |
| confidence             | number (0-1)   | Confidence score assigned by the Outcome Classifier    |
| mttd_seconds           | number/null    | Mean Time To Detect in seconds                         |
| matched_evidence_ref   | string/null    | Reference ID of the matched evidence event             |
| causal_chain           | array[string]  | Sequence of reasoning steps that produced the verdict  |
| rule_id                | string         | Identifier of the validated rule                       |
| technique_ref          | string         | MITRE ATT&CK technique reference                       |
 
## Version
Version: 1.0.0
 
## Status
Frozen for Week 1.
