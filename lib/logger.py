import logging
import logging.handlers
import os
import pathlib
import sys


class Log:
    root_logger = None

    def __init__(self, log_fmt=None) -> None:
        """
        sets logging log level and log file directory
        """
        self.rcount = 10
        self.encoding = "utf8"
        self.mode = "a"
        if log_fmt is None:
            self._f = logging.Formatter(
                fmt="%(asctime)s - %(levelname)s [%(name)s] -  %(filename)s:%(lineno)d - %(message)s "
            )
        else:
            self._f = logging.Formatter(fmt=log_fmt)

    def logfile(self, filename: str, log_level: int = logging.INFO) -> None:

        if not self.root_logger:
            self.root_logger = logging.getLogger()

        self.root_logger.setLevel(log_level)
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("asyncssh").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

        dir_name = os.path.dirname(filename)
        pathlib.Path(dir_name).mkdir(parents=True, exist_ok=True)

        file_handler = logging.handlers.RotatingFileHandler(
            filename, mode=self.mode, encoding=self.encoding, maxBytes=10485760, backupCount=self.rcount
        )
        file_handler.setFormatter(self._f)
        file_handler.setLevel(log_level)
        self.root_logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler(stream=sys.stdout)
        stream_handler.setFormatter(self._f)
        stream_handler.setLevel(log_level)
        for hdlr in self.root_logger.handlers:
            if type(hdlr) == logging.StreamHandler:
                return
        self.root_logger.addHandler(stream_handler)

    def reset_logger(self) -> None:
        """ Removes all handlers except StreamHandlers """
        if not self.root_logger:
            self.root_logger = logging.getLogger()
        for hdlr in self.root_logger.handlers:
            if type(hdlr) != logging.StreamHandler:
                self.root_logger.removeHandler(hdlr)
