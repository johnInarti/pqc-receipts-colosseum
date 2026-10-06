# Publishing fractalai-pqc-verify to PyPI

Not published yet: it requires the founder's PyPI account (and its 2FA). Everything else is ready.

```bash
cd python
rm -rf dist build src/*.egg-info
python -m pip install --upgrade build twine
python -m build                      # -> dist/fractalai_pqc_verify-0.1.0-py3-none-any.whl + .tar.gz
python -m twine check dist/*

# optional dry run on TestPyPI first
python -m twine upload --repository testpypi dist/*

# real upload (prompts for an API token: username "__token__", password "pypi-…")
python -m twine upload dist/fractalai_pqc_verify-0.1.0-py3-none-any.whl dist/fractalai_pqc_verify-0.1.0.tar.gz
```

Then verify from a clean environment:

```bash
python -m venv /tmp/v && /tmp/v/bin/pip install fractalai-pqc-verify
/tmp/v/bin/fractalai-verify conformance && /tmp/v/bin/fractalai-verify midas
```

Bump `version` in both `pyproject.toml` and `src/fractalai_pqc_verify/__init__.py` for every new release
(PyPI never accepts the same version twice).
