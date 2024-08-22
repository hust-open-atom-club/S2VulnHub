import logging

from rich.logging import RichHandler

logging.basicConfig(level="NOTSET", format="%(message)s", handlers=[RichHandler()])
logger = logging.getLogger("s2vulhub")
