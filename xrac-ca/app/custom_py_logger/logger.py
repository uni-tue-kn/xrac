from bcolors import Bcolors as b
from time import gmtime, strftime


class Log:
    """
    simple logger
    """

    time_format = "%H:%M:%S"  # %Y-%m-%d %H:%M:%S

    def __init__(self, name="", level=0):
        self.name = name
        self.level = level
        if self.level > 0:
            self.debug = self._disabled
            self.debug2 = self._disabled
        if self.level > 1:
            self.info = self._disabled
            self.info2 = self._disabled
        if self.level > 2:
            self.warning = self._disabled
        if self.level > 3:
            self.error = self._disabled

    def _disabled(self, msg):
        pass

    def _print(self, msg, ch, color=''):
        print("{0} {1}{2}{3} [{4}{6}{3}] {4}{5}{3}"
              .format(strftime(self.time_format, gmtime()),
                      b.BOLD, self.name, b.ENDC, color, msg, ch))

    def debug(self, msg):
        self._print(msg, 'd')

    def debug2(self, msg):
        self._print(msg, 'dd', b.HEADER)

    def info(self, msg):
        self._print(msg, 'i', b.OKBLUE)

    def info2(self, msg):
        self._print(msg, 'ii', b.OKGREEN)

    def warning(self, msg):
        self._print(msg, 'w', b.WARNING)

    def error(self, msg):
        self._print(msg, 'e', b.FAIL)
