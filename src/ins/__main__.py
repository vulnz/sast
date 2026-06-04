"""Allow `python -m ins` to behave like the `ins` console script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
