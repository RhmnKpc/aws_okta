import logging
import sys

import colorlog

from aws_token import AwsToken


def entry_point():
    """Zero-argument entry point for use with setuptools/distribute."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = colorlog.StreamHandler()
    fmt = "%(asctime)-8s (%(bold)s%(log_color)s%(levelname)s%(reset)s) " "%(message)s"
    formatter = colorlog.ColoredFormatter(fmt, datefmt="%H:%M:%S")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    token = AwsToken(sys.argv)
    raise SystemExit(token.main())


if __name__ == "__main__":
    entry_point()
