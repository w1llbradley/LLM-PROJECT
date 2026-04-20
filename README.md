# Wazuh AI Security Assistant

## Overview

This project is an AI-assisted cybersecurity dashboard that integrates with Wazuh to analyse security alerts using natural language queries.

The system enables a user to:
- Query Wazuh alerts using conversational language
- Generate SOC-style summaries of alerts
- Map alerts to MITRE ATT&CK techniques
- Visualise alert data (e.g. IPs, severity levels)
- Trigger Atomic Red Team simulations
- Run custom attack simulations
- Save and rerun investigations

The solution combines modern security tooling with AI-driven analysis to support faster and more intuitive threat investigation.

---

## System Architecture

The system consists of four main components:

### 1. Streamlit Dashboard (`LLM.py`)
- Provides the user interface and chatbot
- Connects to Wazuh API and OpenSearch
- Sends prompts to the LLM (Ollama)
- Handles alert queries, chart rendering, and investigations

### 2. AI Layer (Ollama)
- Local large language model
- Performs:
  - Intent recognition (routing requests)
  - Alert explanation
  - SOC-style summaries
  - Context-aware follow-up responses

### 3. Security Platform (Wazuh + OpenSearch)
- **Wazuh API**: agent management and alert access
- **OpenSearch Indexer**: stores and retrieves alerts
- Enables filtering, aggregation, and MITRE mapping

### 4. Windows 10 VM (Simulation Environment)
- Runs:
  - Wazuh Agent
  - Sysmon
  - SimRunner (custom PowerShell API)
- Generates realistic attack data through:
  - Atomic Red Team tests
  - Custom simulations

---

## Architecture Diagram

The diagram below illustrates how all system components interact.

![Wazuh AI Architecture](images/diagram.jpeg)

- The user interacts with the Streamlit dashboard  
- The dashboard communicates with:
  - Ollama (AI analysis)
  - Wazuh API and OpenSearch (data retrieval)
  - SimRunner (attack execution)
- SimRunner generates activity → logs → Wazuh agent → Wazuh → OpenSearch → dashboard  

---

## Features

- Natural language alert querying
- MITRE ATT&CK mapping and summaries
- Interactive chart generation (bar and pie charts)
- Atomic Red Team execution via chat commands
- Custom simulation execution via API
- Saved investigation workflows
- Context-aware follow-up explanations

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone <your-gitlab-repo-url>
cd project
2. Install dependencies
pip install -r requirements.txt
3. Configure environment variables

Create a .env file based on .env.example:

cp .env.example .env

Update values accordingly:

OLLAMA_URL=http://127.0.0.1:11434
WAZUH_API=https://<wazuh-ip>:55000
INDEXER_URL=https://<indexer-ip>:9200
SIM_RUNNER_URL=http://<vm-ip>:8766/run
4. Start required services

Ensure the following are running:

Wazuh Manager and Indexer
Wazuh Dashboard (optional)
Ollama with a model installed (e.g. llama3)
Windows VM with:
Wazuh agent configured
Sysmon installed
SimRunner (runner.ps1) running
5. Run the application
streamlit run ollamatest.py
