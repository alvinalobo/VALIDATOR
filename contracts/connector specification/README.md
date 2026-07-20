# Connector Specification

## Purpose

This document defines the standard interface that every SIEM connector must follow. It ensures all connectors behave consistently regardless of the SIEM platform.

## Fields

| Field                    | Type   | Description                     |
|--------------------------|--------|---------------------------------|
| connector_name           | string | Name of the connector           |
| connector_version        | string | Connector version               |
| siem_platform            | string | Supported SIEM platform         |
| supported_query_language | string | Query language used by the SIEM |
| input_rule_format        | string | Accepted rule format (Sigma)    |
| output_format            | string | Format of the returned evidence |
| authentication           | string | Authentication method           |

## Version

Version: 1.0.0

## Status

Frozen for Week 1.