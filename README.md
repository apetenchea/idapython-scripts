# idapython-scripts
A collection of practical IDAPython scripts for automating and extending IDA Pro.

## Setup

```bash
pip install -r requirements.txt
```

## Contribute

Create a recipe in the appropriate `scripts/` folder. Make sure the heading comment contains a title and a
description. See [scripts/core/enumerate_segments.py](scripts/core/enumerate_segments.py) for an example.

## Generate markdown documentation

```bash
python gen.py
mkdocs serve
```