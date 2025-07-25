#!/usr/bin/env python3
# extract_code.py
# Extract source code from analysis results

import json
import argparse
import os
import re
from typing import Dict, List

def read_file_lines(file_path: str, start_line: int, end_line: int = None) -> List[str]:
    """Read specified line range from file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        if end_line is None:
            end_line = start_line
        
        # Convert to 0-based index
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)
        
        return lines[start_idx:end_idx]
    except Exception as e:
        return [f"# Unable to read file: {e}"]

def find_function_at_line(file_path: str, line: int) -> tuple:
    """Find the function containing the specified line"""
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

def read_function_code(file_path: str, line: int) -> tuple:
    """Read complete code of the function containing the specified line"""
    func_name, func_start, func_end = find_function_at_line(file_path, line)
    
    if not func_name:
        return None, [], 0, 0
    
    # Read function code
    func_lines = read_file_lines(file_path, func_start, func_end)
    
    return func_name, func_lines, func_start, func_end

def extract_cross_file_taint_paths(data: Dict, src_dir: str, function_level: bool = False) -> None:
    """Extract source code from cross-file taint paths"""
    paths = data.get('cross_file_taint_paths', [])
    
    if not paths:
        print("No cross-file taint paths found")
        return
    
    level_str = "function-level" if function_level else "line-level"
    print(f"Found {len(paths)} cross-file taint paths ({level_str})")
    print("=" * 60)
    
    for i, path in enumerate(paths[:5], 1):
        print(f"\nPath {i}:")
        print(f"  Source: {path['source_file']}:{path['source_line']}")
        print(f"  Sink: {path['sink_file']}:{path['sink_line']}")
        
        # Extract Source code
        source_file_path = os.path.join(src_dir, path['source_file'])
        
        if function_level:
            # Function-level extraction
            func_name, func_lines, func_start, func_end = read_function_code(source_file_path, path['source_line'])
            print(f"\n  Source function {func_name} ({path['source_file']}:{func_start}-{func_end}):")
            for j, line in enumerate(func_lines):
                line_num = func_start + j
                marker = ">>> " if line_num == path['source_line'] else "    "
                print(f"  {marker}{line_num:4d}: {line.rstrip()}")
        else:
            # Line-level extraction
            source_lines = read_file_lines(source_file_path, path['source_line'])
            print(f"\n  Source code ({path['source_file']}:{path['source_line']}):")
            for j, line in enumerate(source_lines):
                line_num = path['source_line'] + j
                print(f"  {line_num:4d}: {line.rstrip()}")
        
        # Extract Sink code
        sink_file_path = os.path.join(src_dir, path['sink_file'])
        
        if function_level:
            # Function-level extraction
            func_name, func_lines, func_start, func_end = read_function_code(sink_file_path, path['sink_line'])
            print(f"\n  Sink function {func_name} ({path['sink_file']}:{func_start}-{func_end}):")
            for j, line in enumerate(func_lines):
                line_num = func_start + j
                marker = ">>> " if line_num == path['sink_line'] else "    "
                print(f"  {marker}{line_num:4d}: {line.rstrip()}")
        else:
            # Line-level extraction
            sink_lines = read_file_lines(sink_file_path, path['sink_line'])
            print(f"\n  Sink code ({path['sink_file']}:{path['sink_line']}):")
            for j, line in enumerate(sink_lines):
                line_num = path['sink_line'] + j
                print(f"  {line_num:4d}: {line.rstrip()}")

def extract_same_line_sources_sinks(data: Dict, src_dir: str, function_level: bool = False) -> None:
    """Extract source code for same-line sources and sinks"""
    target = data.get('target', {})
    sources = data.get('sources_in_target', [])
    sinks = data.get('sinks_in_target', [])
    
    target_line = target.get('line')
    target_file = target.get('file')
    
    if not target_line or not target_file:
        return
    
    # Find sources and sinks on target line
    line_sources = [s for s in sources if s['line'] == target_line]
    line_sinks = [s for s in sinks if s['line'] == target_line]
    
    if line_sources and line_sinks:
        level_str = "function-level" if function_level else "context"
        print(f"\nSame-line Source/Sink Detection ({level_str})")
        print("=" * 60)
        print(f"File: {target_file}")
        print(f"Line: {target_line}")
        
        file_path = os.path.join(src_dir, target_file)
        
        if function_level:
            # Function-level extraction
            func_name, func_lines, func_start, func_end = read_function_code(file_path, target_line)
            print(f"\nFunction {func_name} ({func_start}-{func_end}):")
            for j, line in enumerate(func_lines):
                line_num = func_start + j
                marker = ">>> " if line_num == target_line else "    "
                print(f"{marker}{line_num:4d}: {line.rstrip()}")
        else:
            # Context code (3 lines before and after)
            context_lines = read_file_lines(file_path, target_line - 3, target_line + 3)
            print(f"\nCode context:")
            for j, line in enumerate(context_lines):
                line_num = target_line - 3 + j
                marker = ">>> " if line_num == target_line else "    "
                print(f"{marker}{line_num:4d}: {line.rstrip()}")
        
        print(f"\nDetected Sources:")
        for src in line_sources:
            print(f"  - {src['pattern']}")
        
        print(f"\nDetected Sinks:")
        for sink in line_sinks:
            print(f"  - {sink['pattern']}")

def extract_function_chains(data: Dict, src_dir: str) -> None:
    """Extract source code from function call chains"""
    chains = data.get('function_chains', [])
    
    if not chains:
        return
    
    print(f"\nFunction call chains (showing first 3)")
    print("=" * 60)
    
    for i, chain in enumerate(chains[:3], 1):
        print(f"\nCall chain {i}:")
        
        if 'calling_function' in chain and 'called_function' in chain:
            calling = chain['calling_function']
            called = chain['called_function']
            
            print(f"  {calling['name']} -> {called['name']}")
            
            # Call site code
            calling_file_path = os.path.join(src_dir, calling['file'])
            calling_lines = read_file_lines(calling_file_path, calling['call_line'])
            
            print(f"\n  Call site ({calling['file']}:{calling['call_line']}):")
            for j, line in enumerate(calling_lines):
                line_num = calling['call_line'] + j
                print(f"  {line_num:4d}: {line.rstrip()}")
            
            # Called function definition
            called_file_path = os.path.join(src_dir, called['file'])
            called_lines = read_file_lines(called_file_path, called['definition_line'])
            
            print(f"\n  Function definition ({called['file']}:{called['definition_line']}):")
            for j, line in enumerate(called_lines):
                line_num = called['definition_line'] + j
                print(f"  {line_num:4d}: {line.rstrip()}")

def main():
    parser = argparse.ArgumentParser(description='Extract source code from analysis results')
    parser.add_argument('--result', required=True, help='Analysis result JSON file')
    parser.add_argument('--src', required=True, help='Project source code directory')
    parser.add_argument('--taint-paths', action='store_true', help='Show only cross-file taint paths')
    parser.add_argument('--same-line', action='store_true', help='Show only same-line source/sink')
    parser.add_argument('--function-chains', action='store_true', help='Show only function call chains')
    parser.add_argument('--function-level', action='store_true', help='Extract function-level code (not line-level)')
    args = parser.parse_args()
    
    # Load analysis results
    try:
        with open(args.result, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error: Unable to read result file: {e}")
        return
    
    level_str = "function-level" if args.function_level else "line-level"
    print(f"[EXTRACT] Source Code Extractor ({level_str})")
    print(f"Result file: {args.result}")
    print(f"Source directory: {args.src}")
    
    # Display content based on arguments
    if args.taint_paths:
        extract_cross_file_taint_paths(data, args.src, args.function_level)
    elif args.same_line:
        extract_same_line_sources_sinks(data, args.src, args.function_level)
    elif args.function_chains:
        extract_function_chains(data, args.src)
    else:
        # Show all content
        extract_same_line_sources_sinks(data, args.src, args.function_level)
        extract_cross_file_taint_paths(data, args.src, args.function_level)
        extract_function_chains(data, args.src)
    
    print(f"\nSource code extraction completed")

if __name__ == '__main__':
    main() 