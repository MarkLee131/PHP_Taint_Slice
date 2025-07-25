#!/usr/bin/env python3
# function_call_chain_slicer.py
# Function-level Cross-file Slicer Tool
"""
Function-level Cross-file Slicer Tool

Core Features:
- Given file + line number, locate the containing function
- Use Joern to analyze intra-function taint propagation
- Use custom algorithms to analyze cross-file function call chains
- Output: function call chains + file paths + line numbers

Usage:
    python3 function_call_chain_slicer.py --src ./project --file target.php --line 42
"""

import os
import sys
import subprocess
import argparse
import json
import re
import yaml
from typing import Dict, List, Tuple, Set
from collections import defaultdict, deque

# === Configuration Loading ===
def load_yaml_config(config_file: str = 'config.yaml') -> Tuple[List[str], List[str]]:
    """Load source/sink patterns from YAML configuration file"""
    if not os.path.exists(config_file):
        print(f"Warning: Config file {config_file} not found")
        return [], []
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        sources = []
        sinks = []
        
        # Extract enabled source patterns
        if 'sources' in config:
            for category in config['sources'].values():
                for item in category:
                    if item.get('enabled', False):
                        sources.append(item['pattern'])
        
        # Extract enabled sink patterns
        if 'sinks' in config:
            for category in config['sinks'].values():
                for item in category:
                    if item.get('enabled', False):
                        sinks.append(item['pattern'])
        
        return sources, sinks
        
    except Exception as e:
        print(f"Warning: Failed to read {config_file}: {e}")
        return [], []

# Fallback function for text files (backward compatibility)
def load_patterns_from_file(file_path: str) -> List[str]:
    """Load patterns from text file (fallback)"""
    if not os.path.exists(file_path):
        return []
    
    patterns = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '#' in line:
                    pattern = line.split('#')[0].strip()
                    if pattern:
                        continue
                else:
                    pattern = line
                
                if pattern:
                    patterns.append(pattern)
    except Exception as e:
        print(f"Warning: Failed to read {file_path}: {e}")
    
    return patterns

# === Joern Tools ===
def detect_joern_dir() -> str:
    """Detect Joern installation directory"""
    candidates = [
        os.path.abspath('./joern/joern-cli'),
        os.environ.get('JOERN_DIR', ''),
        '/opt/joern'
    ]
    for path in candidates:
        if path and os.path.isdir(path):
            return path
    raise RuntimeError('Joern directory not found')

def gen_cpg(src_dir: str, joern_dir: str) -> str:
    """Generate CPG file"""
    php2cpg = os.path.join(joern_dir, 'php2cpg')
    cpg_file = 'function_analysis.bin'
    
    if os.path.exists(cpg_file):
        os.remove(cpg_file)
    
    cmd = [php2cpg, src_dir, '-o', cpg_file]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        raise RuntimeError(f'CPG generation failed: {result.stderr}')
    
    return cpg_file

def run_joern_slice(cpg_file: str, file_path: str, line: int, joern_dir: str) -> List[str]:
    """Use joern-slice to get usages"""
    joern_slice = os.path.join(joern_dir, 'joern-slice')
    if not os.path.exists(joern_slice):
        return []
    
    cmd = [joern_slice, 'usages', cpg_file, '--file', file_path, '--line', str(line)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        return []
    
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]

# === Function Analysis ===
def find_function_at_line(file_path: str, line: int) -> Tuple[str, int, int]:
    """Find the function containing the specified line"""
    if not os.path.exists(file_path):
        return None, None, None
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return None, None, None
    
    # PHP function definition pattern
    func_pattern = re.compile(r'^\s*(?:public|private|protected)?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', re.IGNORECASE)
    
    current_func = None
    func_start = None
    
    for i, code_line in enumerate(lines):
        line_num = i + 1
        
        # Check function definition
        match = func_pattern.search(code_line)
        if match:
            if current_func and func_start and func_start <= line <= line_num - 1:
                # Found target line in current function
                return current_func, func_start, line_num - 1
            current_func = match.group(1)
            func_start = line_num
    
    # Check last function
    if current_func and func_start and func_start <= line <= len(lines):
        return current_func, func_start, len(lines)
    
    # If not in any function, return global code
    return 'global', 1, len(lines)

def extract_function_calls(file_path: str) -> List[Dict]:
    """Extract all function calls from file"""
    if not os.path.exists(file_path):
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return []
    
    calls = []
    # Function call patterns
    call_patterns = [
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',  # Regular function call
        r'\$([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',  # Variable function call
        r'->([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',  # Object method call
        r'::([a-zA-Z_][a-zA-Z0-9_]*)\s*\('   # Static method call
    ]
    
    for line_num, line_content in enumerate(lines, 1):
        for pattern in call_patterns:
            matches = re.finditer(pattern, line_content)
            for match in matches:
                func_name = match.group(1)
                if func_name not in ['if', 'while', 'for', 'foreach', 'switch', 'echo', 'print']:
                    calls.append({
                        'function': func_name,
                        'line': line_num,
                        'code': line_content.strip()
                    })
    
    return calls

def find_function_definitions(src_dir: str) -> Dict[str, List[Dict]]:
    """Find all function definitions"""
    definitions = defaultdict(list)
    
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, src_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                except Exception:
                    continue
                
                func_pattern = re.compile(r'^\s*(?:public|private|protected)?\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', re.IGNORECASE)
                
                for line_num, line_content in enumerate(lines, 1):
                    match = func_pattern.search(line_content)
                    if match:
                        func_name = match.group(1)
                        definitions[func_name].append({
                            'file': rel_path,
                            'line': line_num,
                            'code': line_content.strip()
                        })
    
    return dict(definitions)

def build_function_call_graph(src_dir: str) -> Dict[str, List[Dict]]:
    """Build function call graph"""
    call_graph = defaultdict(list)
    
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, src_dir)
                
                calls = extract_function_calls(file_path)
                for call in calls:
                    call['caller_file'] = rel_path
                    call_graph[call['function']].append(call)
    
    return dict(call_graph)

def analyze_sources_sinks_in_project(src_dir: str, sources: List[str], sinks: List[str]) -> Tuple[Dict, Dict]:
    """Analyze sources and sinks across the entire project"""
    all_sources = {}
    all_sinks = {}
    
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, src_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                except Exception:
                    continue
                
                file_sources = []
                file_sinks = []
                
                for line_num, line_content in enumerate(lines, 1):
                    # Check sources
                    for pattern in sources:
                        if re.search(pattern, line_content):
                            file_sources.append({
                                'line': line_num,
                                'code': line_content.strip(),
                                'pattern': pattern,
                                'file': rel_path
                            })
                    
                    # Check sinks
                    for pattern in sinks:
                        if re.search(pattern, line_content):
                            file_sinks.append({
                                'line': line_num,
                                'code': line_content.strip(),
                                'pattern': pattern,
                                'file': rel_path
                            })
                
                if file_sources:
                    all_sources[rel_path] = file_sources
                if file_sinks:
                    all_sinks[rel_path] = file_sinks
    
    return all_sources, all_sinks

def analyze_sources_sinks(file_path: str, sources: List[str], sinks: List[str]) -> Tuple[List[Dict], List[Dict]]:
    """Analyze sources and sinks in a file"""
    if not os.path.exists(file_path):
        return [], []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return [], []
    
    found_sources = []
    found_sinks = []
    
    for line_num, line_content in enumerate(lines, 1):
        # Check sources
        for pattern in sources:
            if re.search(pattern, line_content):
                found_sources.append({
                    'line': line_num,
                    'code': line_content.strip(),
                    'pattern': pattern
                })
        
        # Check sinks
        for pattern in sinks:
            if re.search(pattern, line_content):
                found_sinks.append({
                    'line': line_num,
                    'code': line_content.strip(),
                    'pattern': pattern
                })
    
    return found_sources, found_sinks

def find_include_dependencies(src_dir: str) -> Dict[str, List[str]]:
    """Find include dependencies between files"""
    dependencies = defaultdict(list)
    
    include_patterns = [
        r'include\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
        r'include_once\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
        r'require\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
        r'require_once\s*\(\s*[\'"]([^\'\"]+)[\'"]\s*\)',
        # Support include statements without parentheses but with quotes
        r'include\s+[\'"]([^\'\"]+)[\'"]',
        r'include_once\s+[\'"]([^\'\"]+)[\'"]',
        r'require\s+[\'"]([^\'\"]+)[\'"]',
        r'require_once\s+[\'"]([^\'\"]+)[\'"]',
        # Support include statements without quotes
        r'include\s+([a-zA-Z0-9_\-\.\/]+\.php)',
        r'include_once\s+([a-zA-Z0-9_\-\.\/]+\.php)',
        r'require\s+([a-zA-Z0-9_\-\.\/]+\.php)',
        r'require_once\s+([a-zA-Z0-9_\-\.\/]+\.php)'
    ]
    
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.php'):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, src_dir)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue
                
                for pattern in include_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        included_file = match.strip()
                        if included_file and not included_file.startswith('$'):
                            # Handle relative paths
                            if included_file.startswith('./') or included_file.startswith('../'):
                                base_dir = os.path.dirname(rel_path)
                                resolved = os.path.normpath(os.path.join(base_dir, included_file))
                            elif not included_file.startswith('/'):
                                # Relative path, relative to current file directory
                                base_dir = os.path.dirname(rel_path)
                                resolved = os.path.normpath(os.path.join(base_dir, included_file))
                            else:
                                resolved = included_file
                            
                            # Check if file exists, save original path if not
                            full_path = os.path.join(src_dir, resolved)
                            if os.path.exists(full_path):
                                dependencies[rel_path].append(resolved)
                            else:
                                # Also save original filename for matching if resolved path doesn't exist
                                dependencies[rel_path].append(included_file)
    
    return dict(dependencies)

# === Main Analysis Pipeline ===
def main():
    parser = argparse.ArgumentParser(description='Function-level Cross-file Slicer Tool')
    parser.add_argument('--src', required=True, help='Project source code directory')
    parser.add_argument('--file', required=True, help='Target file path')
    parser.add_argument('--line', required=True, type=int, help='Target line number')
    parser.add_argument('--output', default='function_chains.json', help='Output file')
    parser.add_argument('--config', default='config.yaml', help='Configuration file (YAML)')
    parser.add_argument('--sources', help='Source patterns file (text, fallback)')
    parser.add_argument('--sinks', help='Sink patterns file (text, fallback)')
    args = parser.parse_args()

    print(f'[ANALYSIS] Function-level Cross-file Slicer')
    print(f'Target: {args.file}:{args.line}')

    # 1. Load source/sink patterns
    if args.sources and args.sinks:
        # Use text files (backward compatibility)
        sources = load_patterns_from_file(args.sources)
        sinks = load_patterns_from_file(args.sinks)
        print(f'Loaded {len(sources)} sources and {len(sinks)} sinks from text files')
    else:
        # Use YAML config
        sources, sinks = load_yaml_config(args.config)
        print(f'Loaded {len(sources)} sources and {len(sinks)} sinks from {args.config}')

    # 2. Locate target function
    target_file_abs = os.path.join(args.src, args.file)
    func_name, func_start, func_end = find_function_at_line(target_file_abs, args.line)
    
    if not func_name:
        print(f'Error: Unable to locate function containing target line')
        sys.exit(1)
    
    print(f'Target function: {func_name} (lines {func_start}-{func_end})')

    # 3. Joern analysis
    try:
        joern_dir = detect_joern_dir()
        cpg_file = gen_cpg(args.src, joern_dir)
        joern_usages = run_joern_slice(cpg_file, args.file, args.line, joern_dir)
        print(f'Joern analysis: {len(joern_usages)} usages found')
    except Exception as e:
        print(f'Warning: Joern analysis failed: {e}')
        joern_usages = []

    # 4. Build function call graph
    print('Building function call graph...')
    function_defs = find_function_definitions(args.src)
    call_graph = build_function_call_graph(args.src)
    print(f'Found {len(function_defs)} function definitions, {len(call_graph)} call relationships')

    # 5. Analyze project-wide sources/sinks
    print('Analyzing project-wide sources/sinks...')
    all_sources, all_sinks = analyze_sources_sinks_in_project(args.src, sources, sinks)
    print(f'Project-wide: {sum(len(s) for s in all_sources.values())} sources, {sum(len(s) for s in all_sinks.values())} sinks')

    # 6. Analyze target file sources/sinks
    target_sources, target_sinks = analyze_sources_sinks(target_file_abs, sources, sinks)
    print(f'Target file: {len(target_sources)} sources, {len(target_sinks)} sinks')

    # 7. Find include dependencies
    print('Analyzing file dependencies...')
    include_deps = find_include_dependencies(args.src)
    print(f'Found {len(include_deps)} files with include dependencies')

    # 8. Build cross-file taint propagation paths
    print('Building cross-file taint propagation paths...')
    taint_paths = []
    
    # Check if target file is included in other files' dependencies
    files_including_target = []
    target_filename = os.path.basename(args.file)
    
    for file, deps in include_deps.items():
        for dep in deps:
            if args.file == dep or target_filename == dep or target_filename == os.path.basename(dep):
                files_including_target.append(file)
                break
    
    # Check if these files containing target file have sinks
    cross_file_paths = []
    if files_including_target:
        for including_file in files_including_target:
            if including_file in all_sinks:
                for sink in all_sinks[including_file]:
                    path = {
                        'source_file': args.file,
                        'source_line': args.line,
                        'source_sources': target_sources,
                        'sink_file': including_file,
                        'sink_line': sink['line'],
                        'sink_code': sink['code'],
                        'connection_type': 'include_dependency',
                        'include_chain': [args.file, including_file]
                    }
                    cross_file_paths.append(path)

    print(f'Found {len(cross_file_paths)} cross-file taint propagation paths')

    # 9. Build function call chains
    function_chains = []
    
    # Start from target function, find call chains
    if func_name in call_graph:
        for call_info in call_graph[func_name]:
            chain = {
                'target_function': {
                    'name': func_name,
                    'file': args.file,
                    'start_line': func_start,
                    'end_line': func_end,
                    'sources': target_sources,
                    'sinks': target_sinks
                },
                'called_from': {
                    'file': call_info['caller_file'],
                    'line': call_info['line'],
                    'code': call_info['code']
                }
            }
            function_chains.append(chain)

    # Find other functions called by target function
    target_calls = extract_function_calls(target_file_abs)
    for call in target_calls:
        if call['function'] in function_defs:
            for definition in function_defs[call['function']]:
                chain = {
                    'calling_function': {
                        'name': func_name,
                        'file': args.file,
                        'call_line': call['line'],
                        'call_code': call['code']
                    },
                    'called_function': {
                        'name': call['function'],
                        'file': definition['file'],
                        'definition_line': definition['line'],
                        'definition_code': definition['code']
                    }
                }
                function_chains.append(chain)

    # 10. Output results
    result = {
        'target': {
            'file': args.file,
            'line': args.line,
            'function': func_name,
            'start_line': func_start,
            'end_line': func_end
        },
        'joern_usages': joern_usages,
        'function_chains': function_chains,
        'cross_file_taint_paths': cross_file_paths,
        'all_sources': all_sources,
        'all_sinks': all_sinks,
        'include_dependencies': include_deps,
        'sources_in_target': target_sources,
        'sinks_in_target': target_sinks,
        'summary': {
            'total_chains': len(function_chains),
            'cross_file_paths': len(cross_file_paths),
            'project_sources': sum(len(s) for s in all_sources.values()),
            'project_sinks': sum(len(s) for s in all_sinks.values()),
            'target_sources': len(target_sources),
            'target_sinks': len(target_sinks),
            'joern_usages': len(joern_usages)
        }
    }

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    print(f'Results saved to: {args.output}')

    # 8. Clean up temporary files
    if os.path.exists(cpg_file):
        os.remove(cpg_file)

    # 11. Summary report
    print('\n[SUMMARY] Analysis Report:')
    print(f'Target function: {func_name}')
    print(f'Function call chains: {len(function_chains)}')
    print(f'Cross-file taint paths: {len(cross_file_paths)}')
    print(f'Project sources: {sum(len(s) for s in all_sources.values())}')
    print(f'Project sinks: {sum(len(s) for s in all_sinks.values())}')
    
    if cross_file_paths:
        print('\nCross-file taint paths found:')
        for i, path in enumerate(cross_file_paths[:3], 1):
            print(f'  {i}. {path["source_file"]}:{path["source_line"]} -> {path["sink_file"]}:{path["sink_line"]}')
    
    if function_chains:
        print('\nFunction call chains found:')
        for i, chain in enumerate(function_chains[:3], 1):
            if 'called_from' in chain:
                print(f'  {i}. {chain["called_from"]["file"]}:{chain["called_from"]["line"]} -> {func_name}')
            elif 'called_function' in chain:
                print(f'  {i}. {func_name} -> {chain["called_function"]["name"]}')

if __name__ == '__main__':
    main() 