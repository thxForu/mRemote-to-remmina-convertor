import logging
import sys

from src.config import setup_logging, parse_arguments
from src.converter import process_connections

logger = logging.getLogger(__name__)

def main():
    setup_logging()
    args = parse_arguments()

    try:
        process_connections(args)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()