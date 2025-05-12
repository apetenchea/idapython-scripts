# idapython-scripts
A collection of practical IDAPython scripts for automating and extending IDA Pro.

## Setup

```bash
pip install -r requirements.txt
```

## Contribute

1. Create a recipe in the appropriate `scripts/` folder. Make sure the heading comment contains a title and a
  description. See [scripts/core/enumerate_segments.py](scripts/core/enumerate_segments.py) for an example.
2. Add a test in the `tests/` folder.

## Run tests

Run your tests (fast):

```bash
pytest -k your_test_name
```

It might be a good idea to have the IDA executable in your PATH. You can also pass the path to the IDA executable
using the `--ida` argument.

```bash
pytest -k your_test_name --ida /path/to/ida
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