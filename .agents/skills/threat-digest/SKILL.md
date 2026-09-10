---
name: threat-digest
description: >-
  Use this skill to run, configure, and maintain the Intelligent AI Digest for Security,
  Privacy, and Compliance Feeds. It outlines steps for feed ingestion, threat analysis,
  running the web dashboard, and running verification tests.
---

# Threat Digest Skill

This skill defines the operational runbook and workflows for the **Intelligent AI Digest for Security, Privacy, and Compliance Feeds** agent. Use this skill as a guide when modifying or running the agent.

## Core Workflows

### 1. Feed Ingestion & Scraping
To ingest new threats from configured feeds:
*   **API Endpoint**: `GET /api/feeds`
*   **Manual Diagnostics**: Run `python scripts/test_connections.py` or `python scripts/test_xml.py`
*   **Sources Configuration**: Feeds are configured in `config/feeds.json` or through the dashboard UI.

### 2. AI Threat Analysis & Enrichment
To run the LLM-powered analysis on threat feeds:
*   **API Endpoint**: `POST /api/analyze-feed`
*   **Capabilities**: Evaluates raw threat articles, extracts CVEs, checks CISA KEV catalogs, queries NIST NVD for CVSS v3.1 and CWE weakness mapping, correlates MITRE ATT&CK TTPs, and computes contextual organization exposure.

### 3. Dashboard Launch
To launch the interactive dashboard locally:
*   **Dev / Local Server**: `python server.py` (FastAPI on port 8000)
*   **Static Assets**: Served seamlessly from `public/` at `http://localhost:8000/`

### 4. Verification & Testing
To ensure all aggregators and analysis pipelines are functioning correctly:
*   **Connection & Diagnostics Audit**: `python scripts/test_connections.py`
*   **Feed Parsing Verification**: `python scripts/test_xml.py`
*   **Full Endpoints Test**: `python scripts/test_api.py`

## Customization and Expansion
*   **Adding Feed Sources**: Edit `config/feeds.json` to register new RSS, Atom, or API endpoints.
*   **Tuning Prompts & Logic**: Modify `src/services/threat_digest/analyzer.py` and `src/services/threat_digest/tools.py`.
*   **Export Formats**: Leverage `src/services/threat_digest/exporter.py` (Markdown, JSON, HTML).
*   **SBOM Analysis**: Use `POST /api/sbom/audit` in `src/services/threat_digest/sbom.py`.

