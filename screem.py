'''

 SCREEM  -  c0mplh4cks

 a Simple Graphical User Interface for the Terminal

'''





# === Importing Dependencies === #
from os import get_terminal_size







# === ANSI Escape Code Functions/Classes === #
def text(text, fg=False, bg=False, bold=False, italic=False, underline=False, blink=False, inverted=False, end=True):
    arg = []

    if fg: arg += [ "38;2;{};{};{}".format(*fg) ]
    if bg: arg += [ "48;2;{};{};{}".format(*bg) ]
    if bold: arg += [ "1" ]
    if italic: arg += [ "3" ]
    if underline: arg += [ "4" ]
    if blink: arg += [ "5" ]
    if inverted: arg += [ "7" ]

    out = f"\x1b[{ ';'.join(arg) }m{ text }"
    if end: out += "\x1b[0m"

    return out







class cursor:
    def hide():
        print( "\x1b[?25l", end="" )
    def show():
        print( "\x1b[?25h", end="" )


    class move:
        def up(n=1):
            print( f"\x1b[{ n }A", end="" )
        def down(n=1):
            print( f"\x1b[{ n }B", end="" )
        def right(n=1):
            print( f"\x1b[{ n }C", end="" )
        def left(n=1):
            print( f"\x1b[{ n }D", end="" )

        def nextline(n=1):
            print( f"\x1b[{ n }E", end="" )
        def prevline(n=1):
            print( f"\x1b[{ n }F", end="" )

        def position(r=1, c=1):
            print( f"\x1b[{ r };{ c }H", end="" )


    class clear:
        def display(n=0):
            print( f"\x1b[{ n }J", end="\r" )
        def line(n=0):
            print( f"\x1b[{ n }K", end="" )


    class scroll:
        def up(n=1):
            print(f"\x1b[{ n }S", end="" )
        def down(n=1):
            print(f"\x1b[{ n }T", end="" )








# === Screen Class === #
class Screen:
    def __init__(self):
        self.terminalsize()


    def terminalsize(self):
        size = get_terminal_size()
        self.w, self.h = size[0], size[1]-1


    def write(self, txt="", r=1, c=1, opt={}):
        if (0 < r <= self.h) and (0 < c <= self.w):
            cursor.move.position(r, c)
            txt = text( txt, **opt )
            print( txt )


    def clear(self):
        cursor.move.position()
        cursor.clear.display(0)
        cursor.clear.display(1)
        cursor.clear.display(3)


    def clean(self):
        print( "\x1b[0m", end="" )
        self.clear()
        cursor.show()
