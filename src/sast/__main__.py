"""Allow `python -m sast` to behave like the `sast` console script."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
