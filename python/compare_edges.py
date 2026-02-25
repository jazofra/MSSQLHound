#!/usr/bin/env python3
"""
Compare two MSSQLHound JSON output files and identify edge differences.

Usage:
    python3 compare_edges.py <file1.json> <file2.json> [--label1 NAME] [--label2 NAME]

Examples:
    python3 compare_edges.py mssql-go-output.json mssql-ps1-output.json
    python3 compare_edges.py file_a.json file_b.json --label1 "Go" --label2 "PS1"
"""

import json
import sys
import argparse
from collections import defaultdict


def load_json(filepath):
    """Load a JSON file and return parsed data."""
    with open(filepath, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def extract_edges(data):
    """
    Extract edges from the JSON data.
    Handles multiple possible structures:
    - Top-level list of edges
    - Dict with 'data' key containing edges
    - Dict with 'edges' key containing edges
    - Nested structures with 'relationships' key
    """
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Try common key names at top level
        for key in ["data", "edges", "relationships", "rels"]:
            if key in data:
                val = data[key]
                if isinstance(val, list):
                    return val

        # Check nested under 'graph'
        if "graph" in data and isinstance(data["graph"], dict):
            graph = data["graph"]
            for key in ["edges", "relationships", "rels"]:
                if key in graph:
                    val = graph[key]
                    if isinstance(val, list):
                        return val

        # If dict has 'start', 'end', 'kind' — it's a single edge
        if "start" in data and "end" in data and "kind" in data:
            return [data]

        # Look one level deeper
        for key, val in data.items():
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and ("kind" in first or "type" in first):
                    return val

    return []


def build_node_id_mapping(data1, data2):
    """Build a mapping from file1 node IDs to file2 node IDs based on matching node labels/names.

    This handles the case where one file uses SID-based identifiers and the other
    uses hostname-based identifiers for the same nodes.
    """
    nodes1 = []
    nodes2 = []

    if isinstance(data1, dict) and "graph" in data1:
        nodes1 = data1["graph"].get("nodes", [])
    if isinstance(data2, dict) and "graph" in data2:
        nodes2 = data2["graph"].get("nodes", [])

    if not nodes1 or not nodes2:
        return {}

    # Build label -> objectid maps for each file
    # Use (kind, label) as key to avoid collisions across different node types
    def build_label_map(nodes):
        label_map = {}
        for node in nodes:
            objectid = node.get("objectid", "")
            kind = node.get("kind", "")
            label = node.get("label", "")
            props = node.get("properties", {})
            name = props.get("name", "")

            # Use the most specific identifier available
            key = (kind, label or name)
            if key[1]:  # Only if we have a label/name
                label_map[key] = objectid
        return label_map

    map1 = build_label_map(nodes1)
    map2 = build_label_map(nodes2)

    # Build file1_id -> file2_id mapping
    id_mapping = {}
    for key, id1 in map1.items():
        if key in map2:
            id2 = map2[key]
            if id1 != id2:
                id_mapping[id1] = id2

    return id_mapping


def normalize_id(value, id_mapping):
    """Normalize a node identifier using the mapping.

    Handles compound identifiers like 'SID:1433\\database' by normalizing
    the base part and preserving suffixes.
    """
    if not id_mapping or value not in id_mapping:
        # Try prefix matching for compound IDs (e.g., "hostname:1433\db")
        for old_id, new_id in id_mapping.items():
            if value.startswith(old_id):
                return new_id + value[len(old_id):]
        return value
    return id_mapping[value]


def make_edge_key(edge, id_mapping=None):
    """Create a hashable key from an edge for comparison (source, target, kind)."""
    start = edge.get("start", {})
    end = edge.get("end", {})

    # Handle both {"value": "..."} and plain string formats
    if isinstance(start, dict):
        source = start.get("value", start.get("objectid", str(start)))
    else:
        source = str(start)

    if isinstance(end, dict):
        target = end.get("value", end.get("objectid", str(end)))
    else:
        target = str(end)

    # Apply ID normalization if mapping provided
    if id_mapping:
        source = normalize_id(source, id_mapping)
        target = normalize_id(target, id_mapping)

    kind = edge.get("kind", edge.get("type", edge.get("label", "UNKNOWN")))

    return (source, target, kind)


def make_full_edge_key(edge):
    """Create a hashable key from an edge including all properties for exact comparison."""
    return json.dumps(edge, sort_keys=True)


def get_edge_properties(edge):
    """Extract edge properties, excluding the structural fields."""
    props = edge.get("properties", {})
    return props


def normalize_value(v, normalize_ws=False):
    """Normalize a value for comparison (handle type differences like bool vs string)."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        if v.lower() == "true":
            return True
        if v.lower() == "false":
            return False
        if normalize_ws:
            return normalize_whitespace(v)
    return v


def normalize_whitespace(s):
    """Normalize whitespace in a string for comparison.

    Handles differences between PS1 (which embeds text in indented heredocs,
    producing leading whitespace and \\r\\n) and Go (which produces clean text).
    """
    import re

    # Normalize line endings
    s = s.replace("\r\n", "\n")
    # Strip leading/trailing whitespace per line
    lines = s.split("\n")
    lines = [l.strip() for l in lines]
    # Remove empty lines (PS1 often has extra blank lines from indentation)
    lines = [l for l in lines if l]
    # Rejoin
    return "\n".join(lines)


def compare_properties(props1, props2, label1, label2, normalize_ws=False):
    """Compare two property dicts and return differences."""
    diffs = []
    all_keys = sorted(set(list(props1.keys()) + list(props2.keys())))

    for key in all_keys:
        if key in props1 and key not in props2:
            diffs.append(f"  Property '{key}' only in {label1}")
        elif key not in props1 and key in props2:
            diffs.append(f"  Property '{key}' only in {label2}")
        else:
            v1 = normalize_value(props1[key], normalize_ws)
            v2 = normalize_value(props2[key], normalize_ws)
            if v1 != v2:
                # Truncate long values
                s1 = str(v1)
                s2 = str(v2)
                if len(s1) > 120:
                    s1 = s1[:120] + "..."
                if len(s2) > 120:
                    s2 = s2[:120] + "..."
                diffs.append(f"  Property '{key}' differs:")
                diffs.append(f"    {label1}: {s1}")
                diffs.append(f"    {label2}: {s2}")

    return diffs


def main():
    parser = argparse.ArgumentParser(
        description="Compare two MSSQLHound JSON output files and identify edge differences."
    )
    parser.add_argument("file1", help="First JSON file path")
    parser.add_argument("file2", help="Second JSON file path")
    parser.add_argument(
        "--label1", default=None, help="Label for first file (default: filename)"
    )
    parser.add_argument(
        "--label2", default=None, help="Label for second file (default: filename)"
    )
    parser.add_argument(
        "--show-property-diffs",
        action="store_true",
        default=True,
        help="Show property differences for matching edges (default: True)",
    )
    parser.add_argument(
        "--no-property-diffs",
        action="store_true",
        help="Skip showing property differences",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show all edge details including full properties",
    )
    parser.add_argument(
        "--normalize-ids",
        action="store_true",
        help="Normalize node IDs between files using node labels (handles SID vs hostname differences)",
    )
    parser.add_argument(
        "--normalize-whitespace",
        action="store_true",
        help="Normalize whitespace when comparing properties (handles PS1 indentation vs Go clean text)",
    )

    args = parser.parse_args()

    label1 = args.label1 or args.file1.split("/")[-1]
    label2 = args.label2 or args.file2.split("/")[-1]
    show_props = args.show_property_diffs and not args.no_property_diffs

    # Load data
    print(f"Loading {label1}...")
    data1 = load_json(args.file1)
    print(f"Loading {label2}...")
    data2 = load_json(args.file2)

    # Show top-level structure
    print(f"\n{'='*80}")
    print("TOP-LEVEL STRUCTURE")
    print(f"{'='*80}")
    if isinstance(data1, dict):
        print(f"  {label1}: dict with keys {list(data1.keys())}")
    else:
        print(f"  {label1}: {type(data1).__name__} with {len(data1)} items")
    if isinstance(data2, dict):
        print(f"  {label2}: dict with keys {list(data2.keys())}")
    else:
        print(f"  {label2}: {type(data2).__name__} with {len(data2)} items")

    # Extract edges
    edges1 = extract_edges(data1)
    edges2 = extract_edges(data2)

    print(f"\n  {label1}: {len(edges1)} edges extracted")
    print(f"  {label2}: {len(edges2)} edges extracted")

    # Count edge types
    type_counts1 = defaultdict(int)
    type_counts2 = defaultdict(int)

    for e in edges1:
        kind = e.get("kind", e.get("type", "UNKNOWN"))
        type_counts1[kind] += 1
    for e in edges2:
        kind = e.get("kind", e.get("type", "UNKNOWN"))
        type_counts2[kind] += 1

    all_types = sorted(set(list(type_counts1.keys()) + list(type_counts2.keys())))

    print(f"\n{'='*80}")
    print("EDGE TYPE COUNTS")
    print(f"{'='*80}")
    print(f"  {'Edge Type':<45} {label1:>10} {label2:>10}  {'Diff':>8}")
    print(f"  {'-'*45} {'-'*10} {'-'*10}  {'-'*8}")
    for t in all_types:
        c1 = type_counts1.get(t, 0)
        c2 = type_counts2.get(t, 0)
        diff = c1 - c2
        diff_str = f"+{diff}" if diff > 0 else str(diff) if diff != 0 else ""
        marker = " <---" if diff != 0 else ""
        print(f"  {t:<45} {c1:>10} {c2:>10}  {diff_str:>8}{marker}")

    total1 = sum(type_counts1.values())
    total2 = sum(type_counts2.values())
    print(f"  {'-'*45} {'-'*10} {'-'*10}  {'-'*8}")
    print(f"  {'TOTAL':<45} {total1:>10} {total2:>10}  {total1-total2:>+8}")

    # Build ID normalization mapping if requested
    id_mapping = None
    if args.normalize_ids:
        id_mapping = build_node_id_mapping(data1, data2)
        if id_mapping:
            print(f"\n  ID normalization: mapped {len(id_mapping)} node IDs from {label1} to {label2}")
        else:
            print(f"\n  ID normalization: no mappable differences found")

    # Build edge maps by key (source, target, kind)
    edges1_by_key = defaultdict(list)
    edges2_by_key = defaultdict(list)

    for e in edges1:
        key = make_edge_key(e, id_mapping)
        edges1_by_key[key].append(e)
    for e in edges2:
        key = make_edge_key(e)
        edges2_by_key[key].append(e)

    keys1 = set(edges1_by_key.keys())
    keys2 = set(edges2_by_key.keys())

    only_in_1 = keys1 - keys2
    only_in_2 = keys2 - keys1
    in_both = keys1 & keys2

    print(f"\n{'='*80}")
    print("EDGE DIFFERENCE SUMMARY")
    print(f"{'='*80}")
    print(f"  Unique edge keys (source, target, kind):")
    print(f"    Only in {label1}: {len(only_in_1)}")
    print(f"    Only in {label2}: {len(only_in_2)}")
    print(f"    In both: {len(in_both)}")

    # Group differences by edge kind
    only1_by_kind = defaultdict(list)
    only2_by_kind = defaultdict(list)

    for key in only_in_1:
        _, _, kind = key
        only1_by_kind[kind].append(key)
    for key in only_in_2:
        _, _, kind = key
        only2_by_kind[kind].append(key)

    # Show edges only in file 1
    if only_in_1:
        print(f"\n{'='*80}")
        print(f"EDGES ONLY IN {label1} ({len(only_in_1)} edges)")
        print(f"{'='*80}")
        for kind in sorted(only1_by_kind.keys()):
            edges_of_kind = only1_by_kind[kind]
            print(f"\n  --- {kind} ({len(edges_of_kind)} edges) ---")
            for source, target, k in sorted(edges_of_kind):
                print(f"    {source}")
                print(f"      -> {target}")
                if args.verbose:
                    for e in edges1_by_key[(source, target, k)]:
                        props = get_edge_properties(e)
                        for pk, pv in sorted(props.items()):
                            sv = str(pv)
                            if len(sv) > 100:
                                sv = sv[:100] + "..."
                            print(f"         {pk}: {sv}")
                print()

    # Show edges only in file 2
    if only_in_2:
        print(f"\n{'='*80}")
        print(f"EDGES ONLY IN {label2} ({len(only_in_2)} edges)")
        print(f"{'='*80}")
        for kind in sorted(only2_by_kind.keys()):
            edges_of_kind = only2_by_kind[kind]
            print(f"\n  --- {kind} ({len(edges_of_kind)} edges) ---")
            for source, target, k in sorted(edges_of_kind):
                print(f"    {source}")
                print(f"      -> {target}")
                if args.verbose:
                    for e in edges2_by_key[(source, target, k)]:
                        props = get_edge_properties(e)
                        for pk, pv in sorted(props.items()):
                            sv = str(pv)
                            if len(sv) > 100:
                                sv = sv[:100] + "..."
                            print(f"         {pk}: {sv}")
                print()

    # Show property differences for matching edges
    if show_props and in_both:
        prop_diff_count = 0
        prop_diff_details = defaultdict(list)

        for key in sorted(in_both):
            source, target, kind = key
            e1_list = edges1_by_key[key]
            e2_list = edges2_by_key[key]

            # Compare first edge of each (most common case: 1:1 match)
            # If there are multiple edges with same key, compare pairwise
            max_len = max(len(e1_list), len(e2_list))

            if len(e1_list) != len(e2_list):
                prop_diff_count += 1
                prop_diff_details[kind].append(
                    f"  {source} -> {target}\n"
                    f"    Count mismatch: {label1} has {len(e1_list)}, {label2} has {len(e2_list)}"
                )
                continue

            for i in range(min(len(e1_list), len(e2_list))):
                props1 = get_edge_properties(e1_list[i])
                props2 = get_edge_properties(e2_list[i])
                diffs = compare_properties(props1, props2, label1, label2, args.normalize_whitespace)
                if diffs:
                    prop_diff_count += 1
                    detail = f"  {source} -> {target}\n" + "\n".join(diffs)
                    prop_diff_details[kind].append(detail)

        if prop_diff_count > 0:
            print(f"\n{'='*80}")
            print(f"PROPERTY DIFFERENCES IN MATCHING EDGES ({prop_diff_count} edges differ)")
            print(f"{'='*80}")
            for kind in sorted(prop_diff_details.keys()):
                details = prop_diff_details[kind]
                print(f"\n  --- {kind} ({len(details)} edges with property diffs) ---")
                for d in details:
                    print(d)
                    print()
        else:
            print(f"\n{'='*80}")
            print("PROPERTY DIFFERENCES: None found for matching edges")
            print(f"{'='*80}")

    # Summary
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"  {label1}: {total1} total edges, {len(all_types)} edge types")
    print(f"  {label2}: {total2} total edges, {len(all_types)} edge types")
    print(f"  Only in {label1}: {len(only_in_1)} edges across {len(only1_by_kind)} types")
    print(f"  Only in {label2}: {len(only_in_2)} edges across {len(only2_by_kind)} types")
    if show_props:
        print(f"  Matching edges with property differences: {prop_diff_count}")


if __name__ == "__main__":
    main()
