import argparse
import ast
from pathlib import Path
import yaml


def parse_metadata_and_code(py_path: Path):
    source = py_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    doc = ast.get_docstring(tree)
    if doc is None:
        raise Exception("no docstring found")
    meta = yaml.safe_load(doc)

    code = None
    header = 2
    lines = source.splitlines()
    for idx, line in enumerate(lines):
        if line.strip() == '"""':
            header -= 1
            if header == 0:
                code = "\n".join(lines[idx + 1:])
                break
    if code is None:
        raise Exception("no code found")

    return meta, code


def convert_file(py_path: Path, input_root: Path, output_root: Path, nav_map: dict):
    try:
        meta, code = parse_metadata_and_code(py_path)
    except Exception as e:
        print(f"Error parsing {py_path}: {e}")
        return

    rel = py_path.relative_to(input_root).with_suffix(".md")
    out_path = output_root / rel
    out_path.parent.mkdir(parents=True, exist_ok=True)
    category = out_path.parent.name.capitalize()

    title = meta.get("title").strip()
    desc  = meta.get("description").strip()

    if category not in nav_map:
        nav_map[category] = list()
    nav_map[category].append({meta.get("title"): rel.as_posix()})

    lines = list()

    # Markdown header
    lines.append(f"# {title}\n")
    if desc:
        lines.append(desc + "\n")

    # Fenced code block
    lines.append("```python")
    lines.append(code.rstrip())
    lines.append("```")

    out_path.write_text("\n".join(lines) + "\n", encoding='utf-8')
    print(f"{out_path}")


def convert_mkdocs(nav_map: dict):
    mk = {
        "site_name": "IDAPython Scripts",
        "theme": {
            "name": "material",
            "palette": [
                {
                    "scheme": "slate",
                    "primary": "blue",
                    "accent": "indigo",
                    "toggle": {
                        "icon": "material/weather-sunny",
                        "name": "Switch to light mode",
                    }
                },
                {
                    "scheme": "default",
                    "primary": "blue",
                    "accent": "indigo",
                    "toggle": {
                        "icon": "material/weather-night",
                        "name": "Switch to dark mode",
                    }
                },
            ],
        },
        "nav": []
    }

    mk["nav"].append({"Home": "index.md"})
    for category, entries in nav_map.items():
        mk["nav"].append({category: entries})

    mk["markdown_extensions"] = [
        "codehilite",
        "admonition",
        "pymdownx.highlight",
        "pymdownx.superfences"
    ]
    mk["plugins"] = ["search"]

    with open("mkdocs.yml", "w") as f:
        yaml.dump(mk, f, sort_keys=False)
    print(f"Generated mkdocs.yml")


def convert(input_root: Path, output_root: Path):
    nav_map = dict()
    for script in input_root.rglob("*.py"):
        convert_file(script, input_root, output_root, nav_map)
    convert_mkdocs(nav_map)


def main():
    parser = argparse.ArgumentParser(
        description="Convert IDAPython scripts to Markdown files."
    )
    parser.add_argument(
        "--input-dir", type=Path, default="scripts",
        help="Root directory of your .py recipe files (e.g. scripts/)"
    )
    parser.add_argument(
        "--output-dir", type=Path, default="docs",
        help="Destination directory for generated .md files (e.g. docs)"
    )
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        parser.error(f"Input directory not found: {args.input_dir}")
    convert(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()
