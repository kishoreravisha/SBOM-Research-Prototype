# SBOM Research Prototype

This prototype is designed for your research paper implementation phase.

## What it does
- Generates an SBOM from a target software project using **Syft**
- Extracts direct and transitive dependencies
- Connects to live vulnerability sources:
  - **OSV API**
  - **NVD CVE API**
- Computes a simple dependency-aware cyber risk score
- Shows output in:
  - terminal mode
  - Streamlit dashboard mode

## Project files
- `scanner_core.py` -> core SBOM scanning and CVE enrichment logic
- `cli.py` -> terminal output
- `dashboard.py` -> simple dashboard
- `requirements.txt` -> Python packages
- `.env.example` -> optional NVD API key template

## 1) Install Python packages
```bash
pip install -r requirements.txt
```

## 2) Install Syft
On Linux:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

Check:
```bash
syft version
```

## 3) Optional NVD API key
Create a `.env` file in the same folder:
```env
NVD_API_KEY=your_nvd_api_key_here
```

## 4) Run in terminal
```bash
python cli.py /path/to/your/project
```

## 5) Run dashboard
```bash
streamlit run dashboard.py
```

## Suggested demo flow for research paper
1. Take one sample software project
2. Run SBOM generation
3. Show extracted direct and transitive dependencies
4. Show live vulnerability lookup
5. Show CVSS + risk ranking
6. Explain that this is the foundation for full dependency-aware cyber risk assessment

## Suggested sample targets
- Python project with `requirements.txt`
- Node.js project with `package.json`
- Maven/Java project with `pom.xml`
