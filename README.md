# Function-level Cross-file Taint Path Extractor

A lightweight tool for analyzing taint paths in PHP projects using Joern and custom cross-file analysis.

## 📁 Main Files

- `function_call_chain_slicer.py` - Core analyzer
- `extract_code.py` - Source code extractor  
- `config.yaml` - Source/sink configuration (YAML)
- `sources.txt` / `sinks.txt` - Legacy text configs (optional)

## 🚀 Quick Start

```bash
# Analyze with YAML config (default)
python3 function_call_chain_slicer.py \
    --src ./src/CVE-2020-15716/rosariosis-v6.7.2 \
    --file modules/Users/Preferences.php \
    --line 127

# Analyze with custom config
python3 function_call_chain_slicer.py \
    --src ./project \
    --file target.php \
    --line 42 \
    --config my_config.yaml

# Analyze with legacy text files
python3 function_call_chain_slicer.py \
    --src ./project \
    --file target.php \
    --line 42 \
    --sources sources.txt \
    --sinks sinks.txt
```

## 📄 Extract Source Code

Extract relevant source code from analysis results:

```bash
# Extract all source code (line-level)
python3 extract_code.py --result result.json --src <project_dir>

# Extract function-level code
python3 extract_code.py --result result.json --src <project_dir> --function-level

# Extract only cross-file taint paths (function-level)
python3 extract_code.py --result result.json --src <project_dir> --taint-paths --function-level

# Extract only same-line source/sink (function-level)
python3 extract_code.py --result result.json --src <project_dir> --same-line --function-level
```

## ⚙️ Configuration

Edit `config.yaml` to customize patterns:

```yaml
sources:
  user_input:
    - pattern: "\\$_GET\\["
      enabled: true
    - pattern: "\\$_POST\\["
      enabled: true
    - pattern: "\\$_COOKIE\\["
      enabled: false  # disabled

sinks:
  output:
    - pattern: "echo\\s+"
      enabled: true
    - pattern: "print\\s+"
      enabled: true
```

## 📊 Output

Analysis results saved to JSON file containing:
- Cross-file taint paths
- Function call chains  
- Source/sink detections
- File dependencies

## 🧪 Test Cases

**CVE-2020-15716**: Same-line source (`$_REQUEST`) and sink (`echo`)  
**CVE-2024-41358**: Cross-file taint from `import-load-data.php` to `import-devices-preview.php`

## 🔧 Dependencies

- Python 3.7+
- PyYAML>=6.0
- Joern (code analysis platform)
- PHP projects for analysis

## 📈 Features

- Same-line Source/Sink detection  
- Cross-file taint propagation analysis  
- Function-level call chains  
- Configurable Source/Sink patterns  
- Joern CPG integration
