# Contributing to parsedmarc

## Bug reports

Please report bugs on the GitHub issue tracker

<https://github.com/domainaware/parsedmarc/issues>

## Local validation

Before opening a PR, run the same core checks used in CI:

```bash
ruff check .
cd docs && make html && cd ..
pytest --cov --cov-report=xml tests.py
```
