"""Terminal Format"""
#============================= colorama =============================
# Fore: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
# Back: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
# Style: DIM, NORMAL, BRIGHT, RESET_ALL
#====================================================================
from colorama import init, Fore, Style

from .common import os_check
from .common import singleton


# wrap must be True when the os is windows
if os_check() == 'windows': init(wrap=True)


def _style(s, style):
    styles = {'dim': Style.DIM, 'normal': Style.NORMAL, 'bright': Style.BRIGHT}
    if style not in styles: style = 'normal'
    return styles[style] + s + Style.RESET_ALL


@singleton
class ColorPalette:

    @staticmethod
    def red(s, style='normal'):
        return _style(Fore.RED + str(s) + Fore.RESET, style)

    @staticmethod
    def black(s, style='normal'):
        return _style(Fore.BLACK + str(s) + Fore.RESET, style)

    @staticmethod
    def green(s, style='normal'):
        return _style(Fore.GREEN + str(s) + Fore.RESET, style)

    @staticmethod
    def yellow(s, style='normal'):
        return _style(Fore.YELLOW + str(s) + Fore.RESET, style)

    @staticmethod
    def blue(s, style='normal'):
        return _style(Fore.BLUE + str(s) + Fore.RESET, style)

    @staticmethod
    def magenta(s, style='normal'):
        return _style(Fore.MAGENTA + str(s) + Fore.RESET, style)

    @staticmethod
    def cyan(s, style='normal'):
        return _style(Fore.CYAN + str(s) + Fore.RESET, style)

    @staticmethod
    def white(s, style='normal'):
        return _style(Fore.WHITE + str(s) + Fore.RESET, style)


color = ColorPalette()