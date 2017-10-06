
import logging
import time
import traceback
import threading
from urllib2 import Request as URLRequest
from urllib2 import urlopen, HTTPError
import weakref

input = raw_input

Bitrex_PROTOCOL = ""
Bitrex_NO_FULLDEPTH = False
Bitrex_NO_DEPTH = False
Bitrex_NO_LAG = False
Bitrex_NO_HISTORY = False
Bitrex_HTTP_bitrex.api = False
Bitrex_NO_HTTP_bitrex.api = False


import locale
import math
import os
import sys
import time
import textwrap
import traceback
import threading

sys_out = sys.stdout



HEIGHT_STATUS = 2
HEIGHT_CON = 20
WIDTH_ORDERbitrex_record = 40

COLORS = [["bitrex_price_update", curses.COLOR_BLACK, curses.COLOR_WHITE],
          ["bitrex_price_update_buy", curses.COLOR_BLACK, curses.COLOR_GREEN],
          ["bitrex_price_update_sell", curses.COLOR_BLACK, curses.COLOR_RED],
          ["con_separator", curses.COLOR_BLUE, curses.COLOR_WHITE],
          ["status_text", curses.COLOR_BLACK, curses.COLOR_WHITE],

          ["bitrex_record_text", curses.COLOR_BLACK, curses.COLOR_CYAN],
          ["bitrex_record_bid", curses.COLOR_BLACK, curses.COLOR_GREEN],
          ["bitrex_record_ask", curses.COLOR_BLACK, curses.COLOR_RED],
          ["bitrex_record_own", curses.COLOR_BLACK, curses.COLOR_YELLOW],
          ["bitrex_record_vol", curses.COLOR_BLACK, curses.COLOR_CYAN],

          ["chart_text", curses.COLOR_BLACK, curses.COLOR_WHITE],
          ["chart_up", curses.COLOR_BLACK, curses.COLOR_GREEN],
          ["chart_down", curses.COLOR_BLACK, curses.COLOR_RED],
          ["order_pending", curses.COLOR_BLACK, curses.COLOR_RED],

          ["dialog_text", curses.COLOR_BLUE, curses.COLOR_CYAN],
          ["dialog_sel", curses.COLOR_CYAN, curses.COLOR_BLUE],
          ["dialog_sel_text", curses.COLOR_BLUE, curses.COLOR_YELLOW],
          ["dialog_sel_sel", curses.COLOR_YELLOW, curses.COLOR_BLUE],
          ["dialog_bid_text", curses.COLOR_GREEN, curses.COLOR_BLACK],
          ["dialog_ask_text", curses.COLOR_RED, curses.COLOR_WHITE]]

INI_DEFAULTS = [["bitrex", "exchange", "kraken"],
                ["bitrex", "set_xterm_title", "True"],
                ["bitrex", "dont_truncate_logfile", "False"],
                ["bitrex", "show_orderbitrex_record_stats", "True"],
                ["bitrex", "highlight_changes", "True"],
                ["bitrex", "orderbitrex_record_group", "0"],
                ["bitrex", "orderbitrex_record_sum_total", "False"],
                ["bitrex", "display_right", "history_chart"],
                ["bitrex", "depth_chart_group", "0.00001"],
                ["bitrex", "depth_chart_sum_total", "True"],
                ["bitrex", "show_ticker", "True"],
                ["bitrex", "show_depth", "True"],
                ["bitrex", "show_trade", "True"],
                ["bitrex", "show_trade_own", "True"]]

COLOR_PAIR = {}

def init_colors():
    
    index = 1
    for (name, back, fore) in COLORS:
        if curses.has_colors():
            curses.init_pair(index, fore, back)
            COLOR_PAIR[name] = curses.color_pair(index)
        else:
            COLOR_PAIR[name] = 0
        index += 1

def dump_all_stacks():

    def get_name(thread_id):
        for thread in threading.enumerate():
            if thread.ident == thread_id:
                return thread.name

    ret = "\n# Full stack trace of all running threads:\n"
    for thread_id, stack in sys._current_frames().items():
        ret += "\n# %s (%s)\n" % (get_name(thread_id), thread_id)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            ret += 'File: "%s", line %d, in %s\n' % (filename, lineno, name)
            if line:
                ret += "  %s\n" % (line.strip())
    return ret


    def __init__(self, stdscr):
        \
        self.stdscr = stdscr
        self.posx = 0
        self.posy = 0
        self.width = 10
        self.height = 10
        self.termwidth = 10
        self.termheight = 10
        self.win = None
        self.panel = None
        self.__create_win()

    def __del__(self):
        del self.panel
        del self.win
        curses.panel.update_panels()
        curses.doupdate()

    def calc_size(self):
    
        del self.win
        self.__create_win()

    def addstr(self, *args):
      
        if len(args) > 0:
            line, col = self.win.getyx()
            string = args[0]
            attr = 0
        if len(args) > 1:
            attr = args[1]
        if len(args) > 2:
            line, col, string = args[:3]
            attr = 0
        if len(args) > 3:
            attr = args[3]
        if line >= self.height:
            return
        space_left = self.width - col - 1  # always omit last column, avoids problems.
        if space_left <= 0:
            return
        self.win.addstr(line, col, string[:space_left], attr)

    def addch(self, posy, posx, character, color_pair):
        
    def __init__(self, stdscr, instance):
               if " tick:" in txt:
            if not self.instance.config.get_bool("bitrex", "show_ticker"):
                return
        if "depth:" in txt:
            if not self.instance.config.get_bool("bitrex", "show_depth"):
                return
        if "trade:" in txt:
            if "own order" in txt:
                if not self.instance.config.get_bool("bitrex", "show_trade_own"):
                    return
            else:
                if not self.instance.config.get_bool("bitrex", "show_trade"):
                    return

        col = COLOR_PAIR["bitrex_price_update"]
        if "trade: bid:" in txt:
            col = COLOR_PAIR["bitrex_price_update_buy"] + curses.A_BOLD
        if "trade: ask:" in txt:
            col = COLOR_PAIR["bitrex_price_update_sell"] + curses.A_BOLD
        self.win.addstr("\n" + txt.encode('utf-8'), col)
        self.done_paint()

class PluginConsole(Win):
    """The console window at the bottom"""
    def __init__(self, stdscr, instance):
        """create the console window and connect it to the instance's debug
        callback function"""
        self.instance = instance
        instance.signal_debug.connect(self.slot_debug)
        Win.__init__(self, stdscr)

    def paint(self):
        """just empty the window after resize (I am lazy)"""
        self.win.bkgd(" ", COLOR_PAIR["bitrex_price_update"])
        for i in range(HEIGHT_CON):
            self.win.addstr("\n ", COLOR_PAIR["con_separator"])

    def resize(self):
        """resize and print a log message. Old messages will have been
        lost after resize because of my dumb paint() implementation, so
        at least print a message indicating that fact into the
        otherwise now empty console window"""
        Win.resize(self)
        self.write("### console has been resized")

    def calc_size(self):
        """put it at the bottom of the screen"""
        self.height = HEIGHT_CON
        self.width = self.termwidth - int(self.termwidth / 2) - 1
        self.posy = self.termheight - self.height
        self.posx = self.termwidth - int(self.termwidth / 2) + 1

    def slot_debug(self, dummy_instance, (txt)):
        """this slot will be connected to all plugin debug signals."""
        if (txt.startswith('[s]')):
            self.write(textwrap.fill(txt.replace('[s]', ' '), self.width))

    def write(self, txt):
        """write a line of text, scroll if needed"""
        self.win.addstr("\n ", COLOR_PAIR["con_separator"])
        self.win.addstr(txt, COLOR_PAIR["bitrex_price_update"])
        self.done_paint()

            strategy_manager.unload()
        except Exception:
            debug_tb.append(traceback.format_exc())

        try:
            instance.stop()
        except Exception:
            debug_tb.append(traceback.format_exc())

        try:
            printhook.close()
        except Exception:
            debug_tb.append(traceback.format_exc())

        try:
            logwriter.close()
        except Exception:
            debug_tb.append(traceback.format_exc())

        time.sleep(1)
        try:
            with open("%s.leftovers.log" % config.filename[:-4], "w") as stacklog:
                stacklog.write(dump_all_stacks())
        except Exception as exc:
            print("Failed to write leftover stacktrace logs:", exc)
           # Here it begins. The very first thing is to always set US or GB locale
    for loc in ["en_US.UTF8", "en_GB.UTF8", "en_EN", "en_GB", "C"]:
        try:
            locale.setlocale(locale.LC_NUMERIC, loc)
            break
        except locale.Error:
            continue
 argp = argparse.ArgumentParser(
        description='Live market data monitor and trading bot experimentation framework')
    argp.add_argument('--config',
                      default="bitrex.ini",
                      help="Use different config file (default: %(default)s)")
    argp.add_argument('--add-secret', action="store_true",
                      help="prompt for API secret, encrypt it and then exit")
    argp.add_argument('--strategy', action="store", default="strategy.py",
                      help="name of strategy module files, comma separated list (default: %(default)s)")
    argp.add_argument('--protocol', action="store", default="",
                      help="Bitrex protocol (socketio, websocket or pubnub), ignore setting in .ini")
    argp.add_argument('--no-fulldepth', action="store_true", default=False,
                      help="do not download full depth (useful for debugging)")
    argp.add_argument('--no-depth', action="store_true", default=False,
                      help="do not request depth messages (implies no-fulldeph), useful for low traffic")
    argp.add_argument('--no-lag', action="store_true", default=False,
                      help="do not request order-lag updates, useful for low traffic")
    argp.add_argument('--no-history', action="store_true", default=False,
                      help="do not download full history (useful for debugging)")
    argp.add_argument('--use-http', action="store_true", default=False,
                      help="use http api for trading (more reliable, recommended")
    argp.add_argument('--no-http', action="store_true", default=False,
                      help="use streaming api for trading (problematic when streaming api disconnects often)")
    argp.add_argument('--password', action="store", default=None,
                      help="password for decryption of stored key. This is a dangerous option "
                      + "because the password might end up being stored in the history file "
                      + "of your shell, for example in ~/.bash_history. Use this only when "
                      + "starting it from within a script and then of course you need to "
                      + "keep this start script in a secure place!")
    args = argp.parse_args()

    config = api.ApiConfig(args.config)
    config.init_defaults(INI_DEFAULTS)
    config.filename = args.config
    secret = api.Secret(config)
    secret.password_from_commandline_option = args.password
    if args.add_secret:
        # prompt for secret, encrypt, write to .ini and then exit the program
        secret.prompt_encrypt()
    else:
        strat_mod_list = args.strategy.split(",")
        bitrex.api_PROTOCOL = args.protocol
        bitrex.api_NO_FULLDEPTH = args.no_fulldepth
        bitrex.api_NO_DEPTH = args.no_depth
        bitrex.api_NO_LAG = args.no_lag
        bitrex.api_NO_HISTORY = args.no_history
        bitrex.api_HTTP_API = args.use_http
        bitrex.api_NO_HTTP_API = args.no_http
        if bitrex.api_NO_DEPTH:
            bitrex.api_NO_FULLDEPTH = True

        # if its ok then we can finally enter the curses main loop
        if secret.prompt_decrypt() != secret.S_FAIL_FATAL:
            # Use curses wrapper
            curses.wrapper(curses_loop)
            # curses ended, terminal should be back in normal (cooked) mode

            if len(debug_tb):
                print "\n\n*** error(s) in curses_loop() that caused unclean shutdown:\n"
                for trb in debug_tb:
                    print trb
            else:
              if __name__ == "__main__":
    main()
