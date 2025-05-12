# idapython-scripts
A collection of practical IDAPython scripts for automating and extending IDA Pro.

## Setup

```bash
pip install -r requirements.txt
```

## Contribute

1. Create a recipe in the appropriate `scripts/` folder. Make sure the header contains a title and a description.
  See [scripts/core/enumerate_segments.py](scripts/core/enumerate_segments.py) for an example.
2. Add a test in the `tests/` folder.

## Run tests

Run your tests (fast):

```bash
pytest -k your_test_name
```

Run everything (slow):

```bash
pytest .
```

Watch out for crashes or differences in the output.

## Generate markdown documentation

```bash
python gen.py
mkdocs serve
```