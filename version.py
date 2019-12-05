from isu.utils.logconfig import configure_logging
from . import defines as defines

VERSION_MAJOR = 0
VERSION_MINOR = 1


def product_version():
    return '%s.%s' % (VERSION_MAJOR, VERSION_MINOR)


if __name__ == "__main__":
    rl = configure_logging(defines.LOG_FILE_NAME)
    rl.info('Version = %s' % product_version())
else:
    import logging
    rl = logging.getLogger()

