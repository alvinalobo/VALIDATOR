# Verdict Schema

## Purpose
This schema defines the standard format used by the Validation Engine to publish verdicts after validating detection rules.

## Fields

| Field            | Type      | Description                                           |
|------------------|-----------|-------------------------------------------------------|
| verdict_id       | string    | Unique identifier for the verdict                     |
| rule_id          | string    | Identifier of the validated rule                      |
| status           | string    | Detection result (Detected, Missed, Partial, No Data) |
| confidence_score | number    | Confidence score assigned by the Outcome Classifier   |
| timestamp        | date-time | Time when the verdict was generated                   |
| remarks          | string    | Optional comments or additional information           |

## Version

Version: 1.0.0

## Status

Frozen for Week 1.