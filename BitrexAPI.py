
import base64
import contextlib
from Lib229 import AES
import getpass
import gzip
import hashlib
import inspect
import io
import json
import sys
PY_VERSION = sys.version_info

if PY_VERSION < (2, 7):
    print("Sorry, minimal Python version is 2.7, you have: %d.%d"
          % (PY_VERSION.major, PY_VERSION.minor))
    sys.exit(1)

from ConfigParser import SafeConfigParser

import logging
import time
import traceback
import threading
from urllib2 import Request as URLRequest
from urllib2 import urlopen, HTTPError
import weakref

input = raw_input

FORCE_PROTOCOL = ""
FORCE_NO_FULLDEPTH = False
FORCE_NO_DEPTH = False
FORCE_NO_LAG = False
FORCE_NO_HISTORY = False
FORCE_HTTP_bitrex.api = False
FORCE_NO_HTTP_bitrex.api = False

USER_AGENT = "PyTrader"


def http_request(url, post=None, headers=None):
        def read_gzipped(response):
       
        if response.info().get('Content-Encoding') == 'gzip':
            with io.BytesIO(response.read()) as buf:
                with gzip.GzipFile(fileobj=buf) as unzipped:
                    data = unzipped.read()
        else:
            data = response.read()
        return data

    if not headers:
        headers = {}
    request = URLRequest(url, post, headers)
    request.add_header('Accept-encoding', 'gzip')
    request.add_header('User-Agent', USER_AGENT)
    data = ""
    try:
        with contextlib.closing(urlopen(request, post)) as res:
            data = read_gzipped(res)
    except HTTPError as err:
        data = read_gzipped(err)
    except Exception as exc:
        logging.debug(" exception in http_request: %s" % exc)

    return data

     if not self.instance.client._wait_for_next_info and not self._waiting:
                self.instance.client._wait_for_next_info = True
                self._waiting = True
            if self.instance.client._wait_for_next_info:
                self.debug("[s]Waiting for balances...")
                return

            # Check minimum limits
            if self.instance.wallet[self.quote] <= QUOTE_LIMIT:
                self.debug("[s]%s %s is below minimum of %s, aborting..." % (
                           self.instance.wallet[self.quote],
                           self.quote,
                           QUOTE_LIMIT))
                self.cancel_orders()
                return
            if self.instance.wallet[self.base] <= BASE_LIMIT:
                self.debug("[s]%s %s is below minimum of %s, aborting..." % (
                           self.instance.wallet[self.base],
                           self.base,
                           BASE_LIMIT))
                self.cancel_orders()
                return

            self._waiting = False
            self.debug("[s]Got balances...")
            if ALERT:
                try:
                    if self.instance.orderbook.owns[0].typ == 'bid':
                        sell_alert.play()
                    else:
                        buy_alert.play()
                except:
                    pass
            self.cancel_orders()
            self.place_orders()

    def price_with_fees(self, price):
        # Get our volume at price
        volume_at_price = self.get_buy_at_price(price)

        if volume_at_price > 0:
            bid_or_ask = 'bid'
            price_with_fees = price / ((1 - self.instance.trade_fee / 100) * (1 - self.instance.trade_fee / 100))
            price_with_fees = price - (price_with_fees - price)
        else:
            bid_or_ask = 'ask'
            volume_at_price = -volume_at_price
            price_with_fees = price / ((1 - self.instance.trade_fee / 100) * (1 - self.instance.trade_fee / 100))

        # Calculate fees
        fees_at_price = volume_at_price * self.instance.trade_fee / 100

        self.debug("[s]next %s: %.8f %s @ %.8f %s - fees: %.8f %s - new: %.8f %s" % (
            bid_or_ask,
            volume_at_price,
            self.base,
            price,
            self.quote,
            fees_at_price,
            self.base,
            price_with_fees,
            self.quote))

        # Return the price with fees
        return math.ceil(price_with_fees * 1e8) / 1e8

    def get_next_buy_price(self, center, step_factor):
                price = self.get_forced_price(center, False)
        if not price:
            price = math.ceil((center / step_factor) * 1e8) / 1e8

            if not center:
                self.debug("[s]Waiting for price...")
            elif COMPENSATE_FEES:
                # Decrease our next buy price
                price = self.price_with_fees(price)

        # return mark_own(price)
        return price

    def get_next_sell_price(self, center, step_factor):
                price = self.get_forced_price(center, True)
        if not price:
            price = math.ceil((center * step_factor) * 1e8) / 1e8

            # Compensate the fees on sell price
            if not center:
                self.debug("[s]Waiting for price...")
            elif COMPENSATE_FEES:
                # Increase our next sell price
                price = self.price_with_fees(price)

        # return mark_own(price)
        return price

    def get_forced_price(self, center, need_ask):
        prices = []
        found = glob.glob("_balancer_force_*")
        if len(found):
            for name in found:
                try:
                    price = float(name.split("_")[3])
                    prices.append(price)
                except:
                    pass
            prices.sort()
            if need_ask:
                for price in prices:
                    if price > center * self.step_factor_sell:
                        # return mark_own(price)
                        return price
            else:
                for price in reversed(prices):
                    if price < center / self.step_factor:
                        # return mark_own(price)
                        return price

        return None
def start_thread(thread_func, name=None):
 if len(bitrex.api.wallet):
            total_base = 0
            total_quote = 0
            for c, own_currency in enumerate(bitrex.api.wallet):
                if own_currency == bitrex.api.curr_base and bitrex.api.orderbook.ask:
                    total_base += bitrex.api.wallet[own_currency]
                    total_quote += bitrex.api.wallet[own_currency] * bitrex.api.orderbook.bid
                elif own_currency == bitrex.api.curr_quote and bitrex.api.orderbook.bid:
                    total_quote += bitrex.api.wallet[own_currency]
                    total_base += bitrex.api.wallet[own_currency] / bitrex.api.orderbook.ask

            total_quote = total_quote
            quote_ratio = (total_quote / bitrex.api.orderbook.bid) / total_base
            base_ratio = (total_base / bitrex.api.orderbook.ask) * 100

            datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.write_log('"%s", "%s", %.8f, %.8f, %.8f, %.8f, %.8f, %.8f, %.8f, %.8f, %.8f, %.8f, %.8f, %.8f' % (
                datetime,
                text,
                volume,
                price,
                bitrex.api.trade_fee,
                self.get_price_where_it_was_balanced(),
                bitrex.api.wallet[bitrex.api.curr_quote],
                total_quote,
                QUOTE_COLD,
                quote_ratio,
                bitrex.api.wallet[bitrex.api.curr_base],
                total_base,
                BASE_COLD,
                base_ratio
            ))

    
    thread = threading.Thread(None, thread_func)
    thread.daemon = True
    thread.start()
    if name:
        thread.name = name
    return thread

def pretty_format(something):
    try:
        return pretty_format(json.loads(something))
    except Exception:
        try:
            return json.dumps(something, indent=5)
        except Exception:
            return str(something)


class bitrex.apiConfig(SafeConfigParser):
    

    _DEFAULTS = [["bitrex.api", "base_currency", "XETH"],
                 ["bitrex.api", "quote_currency", "XXBT"],
                 ["bitrex.api", "use_ssl", "True"],
                 ["bitrex.api", "use_plain_old_websocket", "False"],
                 ["bitrex.api", "use_http_bitrex.api", "True"],
                 ["bitrex.api", "use_tonce", "True"],
                 ["bitrex.api", "load_fulldepth", "True"],
                 ["bitrex.api", "load_history", "True"],
                 ["bitrex.api", "history_timeframe", "15"],
                 ["bitrex.api", "secret_key", ""],
                 ["bitrex.api", "secret_secret", ""]]

    def __init__(self, filename):
        self.filename = filename
        SafeConfigParser.__init__(self)
        self.load()
        self.init_defaults(self._DEFAULTS)
         upgrade from deprecated "currency" to "quote_currency"
         todo: remove this piece of code again in a few months
        if self.has_option("bitrex.api", "currency"):
            self.set("bitrex.api", "quote_currency", self.get_string("bitrex.api", "currency"))
            self.remove_option("bitrex.api", "currency")

import Queue
import base64
import hashlib
import threading
import traceback
from bitrex.api import BaseObject, Signal, Timer, start_thread, http_request
from urllib import urlencode
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
import HTMLParser
html_parser = HTMLParser.HTMLParser()

WEBSOCKET_HOST = "bitrex.api.poloniex.com"
HTTP_HOST = "poloniex.com"

class PoloniexComponent(ApplicationSession):

    def onLeave(self, details):
        self.disconnect()

    def onDisconnect(self):
        client = self.config.extra['client']
        if client.reconnect:
            client.reconnect = False
            client.run()
        else:
            reactor.stop()

    def onConnect(self):
        client = self.config.extra['client']
        client.debug(" connected, subscribing needed channels")
        client.connected = True
        client.leave = self.leave

        client.signal_connected(self, None)

        client.request_fulldepth()
        client.request_history()

        client._time_last_subscribed = time.time()

        self.join(self.config.realm)

    @inlineCallbacks
    def onJoin(self, details):
        client = self.config.extra['client']

        def onTicker(*args):
            try:
                if not client._terminating and args[0] == client.pair:
                    client._time_last_received = time.time()
                     print("Ticker event received:", args)

                    translated = {
                        "op": "ticker",
                        "ticker": {
                            'bid': float(args[3]),
                            'ask': float(args[2])
                        }
                    }
                    client.signal_recv(client, translated)
            except Exception as exc:
                client.debug("onTicker exception:", exc)
                client.debug(traceback.format_exc())

        def onBookUpdate(*args):
            try:
                if not client._terminating:
                    data = args[0]
                     print("BookUpdate event:", data)
                    if data['type'] in ('orderBookRemove', 'orderBookModify'):
                        timestamp = time.time()
                        translated = {
                            'op': 'depth',
                            'depth': {
                                'type': data['data']['type'],
                                'price': float(data['data']['rate']),
                                'volume': float(data['data']['amount']) if data['type'] == 'orderBookModify' else 0,
                                'timestamp': timestamp
                            },
                            'id': "depth"
                        }
                        client.signal_recv(client, translated)

                    elif data['type'] == 'newTrade':
                         {
                             data: {
                                 tradeID: '364476',
                                 rate: '0.00300888',
                                 amount: '0.03580906',
                                 date: '2014-10-07 21:51:20',
                                 total: '0.00010775',
                                 type: 'sell'
                             },
                             type: 'newTrade'
                         }
                        data = data['data']
                        client.debug("newTrade:", data)
                        translated = {
                            'op': 'trade',
                            'trade': {
                                'id': data['tradeID'],
                                'type': 'ask' if data['type'] == 'buy' else 'bid',
                                'price': data['rate'],
                                'amount': data['amount'],
                                'timestamp': time.mktime(time.strptime(data['date'], "%Y-%m-%d %H:%M:%S"))
                            }
                        }
                        client.signal_recv(client, translated)
                    else:
                        client.debug("Unknown trade event:", args)

            except Exception as exc:
                client.debug("onBookUpdate exception:", exc)
                client.debug(traceback.format_exc())

        def onTrollbox(*args):
            try:
                if not client._terminating:
                     print("troll:", args)
                     msg = args[0]
                    if len(args) == 5:
                        translated = {
                            "op": "chat",
                            "msg": {
                                'type': args[0],
                                'user': args[2],
                                'msg': html_parser.unescape(args[3]),
                                'rep': args[4]
                            }
                        }
                    else:
                        translated = {
                            "op": "chat",
                            "msg": {
                                "type": args[0],
                                "user": args[1],
                                "msg": "-",
                                "rep": "-"
                            }
                        }
                    client.signal_recv(client, translated)
            except Exception as exc:
                client.debug("onTrollbox exception:", exc)
                client.debug(traceback.format_exc())

        try:
            yield self.subscribe(onBookUpdate, client.pair)
            yield self.subscribe(onTicker, 'ticker')
            yield self.subscribe(onTrollbox, 'trollbox')
        except Exception as exc:
            client.debug("Could not subscribe to topic:", exc)
            client.connected = False
            client.signal_disconnected(client, None)

            if not client._terminating:
                client.debug(" ", exc.__class__.__name__, exc,
                             "reconnecting in %i seconds..." % 1)
                client.force_reconnect()

class BaseClient(BaseObject):

    _last_unique_microtime = 0
    _nonce_lock = threading.Lock()

    def __init__(self, curr_base, curr_quote, secret, config):
         PoloniexComponent.__init__(self, curr_base, curr_quote)

        self.signal_recv = Signal()
        self.signal_ticker = Signal()
        self.signal_connected = Signal()
        self.signal_disconnected = Signal()
        self.signal_fulldepth = Signal()
        self.signal_fullhistory = Signal()

        self._timer = Timer(60)
        self._timer_history = Timer(30)

        self._timer.connect(self.slot_timer)
        self._timer_history.connect(self.slot_history)

        self._info_timer = None   used when delayed requesting private/info

        self.curr_base = curr_base
        self.curr_quote = curr_quote
        self.pair = "%s_%s" % (curr_quote, curr_base)

        self.currency = curr_quote   deprecated, use curr_quote instead

        self.secret = secret
        self.config = config
        self.socket = None

        use_ssl = self.config.get_bool("bitrex.api", "use_ssl")
        self.proto = {True: "https", False: "http"}[use_ssl]
        self.http_requests = Queue.Queue()

        self._recv_thread = None
        self._http_thread = None
        self._terminating = False
        self.reconnect = False
        self.connected = False
        self.leave = None
        self._time_last_received = 0
        self._time_last_subscribed = 0
        self.history_last_candle = None

    def start(self):
        self._recv_thread = start_thread(self._recv_thread_func, "socket receive thread")
        self._http_thread = start_thread(self._http_thread_func, "http thread")

    def stop(self):
        self._terminating = True
        self._timer.cancel()
        self._timer_history.cancel()
        self.debug(" stopping reactor")
        try:
            self.leave()
        except Exception as exc:
            self.debug("Reactor exception:", exc)

    def force_reconnect(self):
        try:
            self.reconnect = True
            self.leave()
        except Exception as exc:
            self.debug("Reactor exception:", exc)
            self.debug(traceback.format_exc())

    def _try_send_raw(self, raw_data):
        if self.connected:
            try:
                self.debug("TODO - Would send: %s" % raw_data)
                 self.socket.send(raw_data)
            except Exception as exc:
                self.debug(exc)
                 self.connected = False

    def send(self, json_str):
       
        raise NotImplementedError()

    def get_unique_mirotime(self):
        with self._nonce_lock:
            microtime = int(time.time() * 1e6)
            if microtime <= self._last_unique_microtime:
                microtime = self._last_unique_microtime + 1
            self._last_unique_microtime = microtime
            return microtime

    def request_fulldepth(self):

        def fulldepth_thread():
            
             self.debug(" requesting full depth")
            json_depth = http_request("%s://%s/public?command=returnOrderBook&currencyPair=%s&depth=500" % (
                self.proto,
                HTTP_HOST,
                self.pair
            ))
            if json_depth and not self._terminating:
                try:
                    fulldepth = json.loads(json_depth)

                     self.debug("Depth: %s" % fulldepth)

                    depth = {}
                    depth['error'] = {}

                    if 'error' in fulldepth:
                        depth['error'] = fulldepth['error']

                    depth['data'] = {'asks': [], 'bids': []}

                    for ask in fulldepth['asks']:
                        depth['data']['asks'].append({
                            'price': float(ask[0]),
                            'amount': float(ask[1])
                        })
                    for bid in reversed(fulldepth['bids']):
                        depth['data']['bids'].append({
                            'price': float(bid[0]),
                            'amount': float(bid[1])
                        })

                    self.signal_fulldepth(self, depth)
                except Exception as exc:
                    self.debug(" exception in fulldepth_thread:", exc)

        start_thread(fulldepth_thread, "http request full depth")

    def request_history(self):
                def history_thread():

            if not self.history_last_candle:
                querystring = "&start=%i&end=%i" % ((time.time() - 172800), (time.time() - 86400))
                 self.debug(" requesting 2d history since %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - 172800)))
            else:
                querystring = "&start=%i" % (self.history_last_candle - 14400)
                 self.debug("Last candle: %s" % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.history_last_candle - 14400)))

            json_hist = http_request("%s://%s/public?command=returnTradeHistory&currencyPair=%s%s" % (
                self.proto,
                HTTP_HOST,
                self.pair,
                querystring
            ))
            if json_hist and not self._terminating:
                try:
                    raw_history = json.loads(json_hist)

                     self.debug("History: %s" % raw_history)

                    history = []
                    for h in reversed(raw_history):
                        history.append({
                            'price': float(h['rate']),
                            'amount': float(h['amount']),
                            'date': time.mktime(time.strptime(h['date'], "%Y-%m-%d %H:%M:%S")) - 480
                        })

                     self.debug("History: %s" % history)

                    if history and not self._terminating:
                        self.signal_fullhistory(self, history)
                except Exception as exc:
                    self.debug(" exception in history_thread:", exc)

        start_thread(history_thread, "http request trade history")

    def _recv_thread_func(self):
       
        raise NotImplementedError()

    def _slot_timer_info_later(self, _sender, _data):
               while not self._terminating:
            try:
                (bitrex.api_endpoint, params, reqid) = self.http_requests.get(True)
                translated = None

                answer = self.http_signed_call(bitrex.api_endpoint, params)
                if "result" in answer:
                                       if bitrex.api_endpoint == 'private/OpenOrders':
                        result = []
                        orders = answer["result"]["open"]
                        for txid in orders:
                            tx = orders[txid]
                            result.append({
                                'oid': txid,
                                'base': "X" + tx['descr']['pair'][0:3],
                                'currency': "X" + tx['descr']['pair'][3:],
                                'status': tx['status'],
                                'type': 'bid' if tx['descr']['type'] == 'buy' else 'ask',
                                'price': float(tx['descr']['price']),
                                'amount': float(tx['vol'])
                            })
                             self.debug("TX: %s" % result)
                    elif bitrex.api_endpoint == 'private/TradeVolume':
                        result = {
                            'volume': float(answer['result']['volume']),
                            'currency': answer['result']['currency'],
                            'fee': float(answer['result']['fees_maker'][self.pair]['fee'])
                        }
                    else:
                        result = answer["result"]

                    translated = {
                        "op": "result",
                        "result": result,
                        "id": reqid
                    }
                else:
                    if "error" in answer:
                        if "token" not in answer:
                            answer["token"] = "-"
                         if answer["token"] == "unknown_error":
                     
                    else:
                        self.debug(" unexpected http result:", answer, reqid)

                if translated:
                    self.signal_recv(self, (json.dumps(translated)))

                self.http_requests.task_done()


        self.debug("Polling terminated...")

    def enqueue_http_request(self, bitrex.api_endpoint, params, reqid):
        if self.secret and self.secret.know_secret():
            self.http_requests.put((bitrex.api_endpoint, params, reqid))

    def http_signed_call(self, bitrex.api_endpoint, params):
        if (not self.secret) or (not self.secret.know_secret()):
            self.debug(" don't know secret, cannot call %s" % bitrex.api_endpoint)
            return

        key = self.secret.key
        sec = self.secret.secret

        params["nonce"] = self.get_unique_mirotime()

        post = urlencode(params)
       
        sign = hmac.new(sec, post, hashlib.sha512).hexdigest()

        headers = {
            'Key': key,
            'Sign': base64.b64encode(sign)
        }

        url = "%s://%s/%s" % (
            self.proto,
            HTTP_HOST,
            bitrex.api_endpoint
        )
         self.debug(" (%s) calling %s" % (self.proto, url))
        try:
            result = json.loads(http_request(url, post, headers))
            return result
        except ValueError as exc:
            self.debug(" exception in http_signed_call:", exc)

    def send_order_add(self, typ, price, volume):
        reqid = "order_add:%s:%f:%f" % (typ, price, volume)
        bitrex.api = 'tradingbitrex.api'
        params = {
            'currencyPair': self.pair,
            'rate': price,
            'amount': volume
        }
        if typ == 'bid':
            params['command'] = 'buy'
        else:
            params['command'] = 'sell'

        self.enqueue_http_request(bitrex.api, params, reqid)

    
            self.save()

    def init_defaults(self, defaults):
               for (sect, opt, default) in defaults:
            self._default(sect, opt, default)

    def save(self):
        with open(self.filename, 'wb') as configfile:
            self.write(configfile)

    def load(self):
        self.read(self.filename)

    def get_safe(self, sect, opt):
        try:
            return self.get(sect, opt)

        except:
            for (dsect, dopt, default) in self._DEFAULTS:
                if dsect == sect and dopt == opt:
                    self._default(sect, opt, default)
                    return default
            return ""

    def get_bool(self, sect, opt):
        return self.get_safe(sect, opt) == "True"

    def get_string(self, sect, opt):
        return self.get_safe(sect, opt)

    def get_int(self, sect, opt):
        vstr = self.get_safe(sect, opt)
        try:
            return int(vstr)
        except ValueError:
            return 0

    def get_float(self, sect, opt):
        vstr = self.get_safe(sect, opt)
        try:
            return float(vstr)
        except ValueError:
            return 0.0

    def _default(self, section, option, default):
        if not self.has_section(section):
            self.add_section(section)
        if not self.has_option(section, option):
            self.set(section, option, default)
            self.save()


class Signal():
        _lock = threading.RLock()
    signal_error = None

    def __init__(self):
        self._functions = weakref.WeakSet()
        self._methods = weakref.WeakKeyDictionary()

               if not Signal.signal_error:
            Signal.signal_error = 1
            Signal.signal_error = Signal()

    def connect(self, slot):
      
        if inspect.ismethod(slot):
            instance = slot.__self__
            function = slot.__func__
            if instance not in self._methods:
                self._methods[instance] = set()
            if function not in self._methods[instance]:
                self._methods[instance].add(function)
        else:
            if slot not in self._functions:
                self._functions.add(slot)

    def __call__(self, sender, data, error_signal_on_error=True):
       
        with self._lock:
            sent = False
            errors = []
            for func in self._functions:
                try:
                    func(sender, data)
                    sent = True

                except:
                    errors.append(traceback.format_exc())

            for instance, functions in self._methods.items():
                for func in functions:
                    try:
                        func(instance, sender, data)
                        sent = True

                    except:
                        errors.append(traceback.format_exc())

            for error in errors:
                if error_signal_on_error:
                    Signal.signal_error(self, (error), False)
                else:
                    logging.critical(error)

            return sent


class BaseObject():
    
    def __init__(self):
        self.signal_debug = Signal()

    def debug(self, *args):
        
        msg = " ".join([unicode(x) for x in args])
        if not self.signal_debug(self, (msg)):
            logging.debug(msg)


class Timer(Signal):

    def __init__(self, interval, one_shot=False):
        Signal.__init__(self)
        self._one_shot = one_shot
        self._canceled = False
        self._interval = interval
        self._timer = None
        self._start()

    def _fire(self):
        if not self._canceled:
            self.__call__(self, None)
            if not (self._canceled or self._one_shot):
                self._start()

    def _start(self):
        self._timer = threading.Timer(self._interval, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def cancel(self):
        self._canceled = True
        self._timer.cancel()
        self._timer = None


class Secret:
        S_OK = 0
    S_FAIL = 1
    S_NO_SECRET = 2
    S_FAIL_FATAL = 3

    def __init__(self, config):
        """initialize the instance"""
        self.config = config
        self.key = ""
        self.secret = ""

        self.password_from_commandline_option = None

    def decrypt(self, password):
               key = self.config.get_string("bitrex.api", "secret_key")
        sec = self.config.get_string("bitrex.api", "secret_secret")
        if sec == "" or key == "":
            return self.S_NO_SECRET

        hashed_pass = hashlib.sha512(password.encode("utf-8")).digest()
        crypt_key = hashed_pass[:32]
        crypt_ini = hashed_pass[-16:]
        aes = AES.new(crypt_key, AES.MODE_OFB, crypt_ini)
        try:
            encrypted_secret = base64.b64decode(sec.strip().encode("ascii"))
            self.secret = aes.decrypt(encrypted_secret).strip()
            self.key = key.strip()
        except ValueError:
            return self.S_FAIL

        try:
            print("testing secret...")
           
            if len(base64.b64decode(self.secret)) != 64:
                raise Exception("Decrypted secret has wrong size")
            if not self.secret:
                raise Exception("Unable to decrypt secret")

            print("testing key...")
                       if not self.key:
                raise Exception("Unable to decrypt key")

            print("OK")
            return self.S_OK

        except Exception as exc:
            self.secret = ""
            self.key = ""
            print(" Error occurred while testing the decrypted secret:")
            print("    '%s'" % exc)
            print("    This does not seem to be a valid bitrex.api secret")
            return self.S_FAIL

    def prompt_decrypt(self):
        and then try to decrypt the secret."""
        if self.know_secret():
            return self.S_OK

        key = self.config.get_string("bitrex.api", "secret_key")
        sec = self.config.get_string("bitrex.api", "secret_secret")
        if sec == "" or key == "":
            return self.S_NO_SECRET

        if self.password_from_commandline_option:
            password = self.password_from_commandline_option
        else:
            password = getpass.getpass("enter passphrase for secret: ")

        result = self.decrypt(password)
        if result != self.S_OK:
            print("")
            print("secret could not be decrypted")
            answer = input("press any key to continue anyways "
                           + "(trading disabled) or 'q' to quit: ")
            if answer == "q":
                result = self.S_FAIL_FATAL
            else:
                result = self.S_NO_SECRET
        return result

    def prompt_encrypt(self):
       
        print("")

        key = input("             key: ").strip()
        secret = input("          secret: ").strip()
        while True:
            password1 = getpass.getpass("        password: ").strip()
            if password1 == "":
                print("aborting")
                return
            password2 = getpass.getpass("password (again): ").strip()
            if password1 != password2:
                print("you had a typo in the password. try again...")
            else:
                break

        hashed_pass = hashlib.sha512(password1.encode("utf-8")).digest()
        crypt_key = hashed_pass[:32]
        crypt_ini = hashed_pass[-16:]
        aes = AES.new(crypt_key, AES.MODE_OFB, crypt_ini)

     
        print(len(secret))
        secret += " " * (16 - len(secret) % 16)
        print(len(secret))
        secret = base64.b64encode(aes.encrypt(secret)).decode("ascii")

        self.config.set("bitrex.api", "secret_key", key)
        self.config.set("bitrex.api", "secret_secret", secret)
        self.config.save()

        print("encrypted secret has been saved in %s" % self.config.filename)

    def know_secret(self):
        
class OHLCV():
   
    def __init__(self, tim, opn, hig, low, cls, vol):
        self.tim = tim
        self.opn = opn
        self.hig = hig
        self.low = low
        self.cls = cls
        self.vol = vol

    def update(self, price, volume):
        if price > self.hig:
            self.hig = price
        if price < self.low:
            self.low = price
        self.cls = price
        self.vol += volume


class History(BaseObject):

    def __init__(self, bitrex.api, timeframe):
        BaseObject.__init__(self)

        self.signal_fullhistory_processed = Signal()
        self.signal_changed = Signal()

        self.bitrex.api = bitrex.api
        self.candles = []
        self.timeframe = timeframe

        self.ready_history = False

        bitrex.api.signal_trade.connect(self.slot_trade)
        bitrex.api.signal_fullhistory.connect(self.slot_fullhistory)

    def add_candle(self, candle):
        self._add_candle(candle)
        self.signal_changed(self, (self.length()))

    def slot_trade(self, dummy_sender, data):
        (date, price, volume, dummy_typ, own) = data
        if not own:
            time_round = int(date / self.timeframe) * self.timeframe
            candle = self.last_candle()
            if candle:
                if candle.tim == time_round:
                    candle.update(price, volume)
                    self.signal_changed(self, (1))
                else:
                    self.debug(" opening new candle")
                    self.add_candle(OHLCV(
                        time_round, price, price, price, price, volume))
            else:
                self.add_candle(OHLCV(
                    time_round, price, price, price, price, volume))

    def _add_candle(self, candle):
        self.candles.insert(0, candle)

    def slot_fullhistory(self, dummy_sender, data):
        (history) = data

        if not len(history):
            self.debug(" history download was empty")
            return

        def get_time_round(date):
            return int(date / self.timeframe) * self.timeframe

        date_begin = get_time_round(history[0]["date"])
        while len(self.candles) and self.candles[0].tim >= date_begin:
            self.candles.pop(0)

        new_candle = OHLCV(0, 0, 0, 0, 0, 0)   this is a dummy, not actually inserted
        count_added = 0
        for trade in history:
            date = trade["date"]
            price = trade["price"]
            volume = trade["amount"]
            time_round = get_time_round(date)
            if time_round > new_candle.tim:
                if new_candle.tim > 0:
                    self._add_candle(new_candle)
                    count_added += 1
                new_candle = OHLCV(time_round, price, price, price, price, volume)
            new_candle.update(price, volume)

        self._add_candle(new_candle)
        count_added += 1
        self.ready_history = True
        self.signal_fullhistory_processed(self, None)
        self.signal_changed(self, (self.length()))

    def last_candle(self):
        if self.length() > 0:
            return self.candles[0]
        else:
            return None

    def length(self):
        return len(self.candles)


class bitrex.api(BaseObject):
       def __init__(self, secret, config):
        """initialize the bitrex.api but do not yet connect to it."""
        BaseObject.__init__(self)

        self.signal_depth = Signal()
        self.signal_trade = Signal()
        self.signal_ticker = Signal()
        self.signal_fulldepth = Signal()
        self.signal_fullhistory = Signal()
        self.signal_wallet = Signal()
        self.signal_userorder = Signal()
        self.signal_orderlag = Signal()
        self.signal_disconnected = Signal()   socket connection lost
        self.signal_ready = Signal()   connected and fully initialized

        self.signal_order_too_fast = Signal()   don't use that

        self.strategies = weakref.WeakValueDictionary()

               self.signal_keypress = Signal()
        self.signal_strategy_unload = Signal()

        self.wallet = {}
        self.trade_fee = 0   percent (float, for example 0.6 means 0.6%)
        self.monthly_volume = 0   variable currency per exchange
        self.order_lag = 0   microseconds
        self.socket_lag = 0   microseconds
        self.last_tid = 0
        self.count_submitted = 0   number of submitted orders not yet acked
        self.msg = {}   the incoming message that is currently processed

       
        self.ready_info = False
        self._was_disconnected = True

        self.config = config
        self.curr_base = config.get_string("bitrex.api", "base_currency")
        self.curr_quote = config.get_string("bitrex.api", "quote_currency")

        self.currency = self.curr_quote   used for monthly_volume currency

        self.exchange = config.get_string("pytrader", "exchange")

        self.mult_quote = 1e5
        self.format_quote = "%12.5f"
        self.mult_base = 1e8
        self.format_base = "%16.8f"

        Signal.signal_error.connect(self.signal_debug)

        timeframe = 60 * config.get_int("bitrex.api", "history_timeframe")
        if not timeframe:
            timeframe = 60 * 15
        self.history = History(self, timeframe)
        self.history.signal_debug.connect(self.signal_debug)

        self.orderbook = OrderBook(self)
        self.orderbook.signal_debug.connect(self.signal_debug)

        use_websocket = self.config.get_bool("bitrex.api", "use_plain_old_websocket")

        if "socketio" in FORCE_PROTOCOL:
            use_websocket = False
        if "websocket" in FORCE_PROTOCOL:
            use_websocket = True
    next_buy = self.bid

            self.debug("[s]corrected next buy at %.8f instead of %.8f, bid price at %.8f" % (next_buy, bad_next_buy, self.bid))
        elif self.bid == 0:
            status_prefix = 'Waiting for price, skipping ' + self.simulate_or_live

        sell_amount = -self.get_buy_at_price(next_sell)
        buy_amount = self.get_buy_at_price(next_buy)

        if sell_amount < 0.1:
            sell_amount = 0.1
            self.debug("[s]WARNING! minimal sell amount adjusted to 0.1")

        if buy_amount < 0.1:
            buy_amount = 0.1
            self.debug("[s]WARNING! minimal buy amount adjusted to 0.1")

        self.debug("[s]%snew buy order %.8f at %.8f for %.8f %s" % (
            status_prefix,
            buy_amount,
            next_buy,
            next_buy * buy_amount,
            self.quote
        ))
        if not self.simulate and self.ask != 0:
            self.instance.buy(next_buy, buy_amount)
        elif self.simulate and self.wallet and self.ask != 0:
            self.simulated.update({"next_buy": next_buy, "buy_amount": buy_amount})

        self.debug("[s]%snew sell order %.8f at %.8f for %.8f %s" % (
            status_prefix,
            sell_amount,
            next_sell,
            next_sell * sell_amount,
            self.quote

        if self.exchange == "gox":   So obsolete...
            if use_websocket:
                from exchanges.gox import WebsocketClient
                self.client = WebsocketClient(self.curr_base, self.curr_quote, secret, config)
            else:
                from exchanges.gox import SocketIOClient
                self.client = SocketIOClient(self.curr_base, self.curr_quote, secret, config)
        elif self.exchange == "kraken":
            from exchanges.kraken import PollClient
            self.client = PollClient(self.curr_base, self.curr_quote, secret, config)
        elif self.exchange == "poloniex":
            from exchanges.poloniex import WebsocketClient
            self.client = WebsocketClient(self.curr_base, self.curr_quote, secret, config)
        else:
            raise Exception("Unsupported exchange")

        self.client.signal_debug.connect(self.signal_debug)
        self.client.signal_disconnected.connect(self.slot_disconnected)
        self.client.signal_connected.connect(self.slot_client_connected)
        self.client.signal_recv.connect(self.slot_recv)
        self.client.signal_fulldepth.connect(self.signal_fulldepth)
        self.client.signal_fullhistory.connect(self.signal_fullhistory)
        self.client.signal_ticker.connect(self.signal_ticker)

        self.timer_poll = Timer(120)
        self.timer_poll.connect(self.slot_poll)

        self.history.signal_changed.connect(self.slot_history_changed)
        self.history.signal_fullhistory_processed.connect(self.slot_fullhistory_processed)
        self.orderbook.signal_fulldepth_processed.connect(self.slot_fulldepth_processed)
        self.orderbook.signal_owns_initialized.connect(self.slot_owns_initialized)

    def start(self):
        self.debug(" Starting bitrex.api, trading %s%s" % (self.curr_base, self.curr_quote))
        self.client.start()

    def stop(self):
        self.debug(" shutdown...")
        self.client.stop()

    def order(self, typ, price, volume):
        self.count_submitted += 1
        self.client.send_order_add(typ, price, volume)

    def buy(self, price, volume):
        self.order("bid", price, volume)

    def sell(self, price, volume):
        self.order("ask", price, volume)

    def cancel(self, oid):
        self.client.send_order_cancel(oid)

    def cancel_by_price(self, price):
        for i in reversed(range(len(self.orderbook.owns))):
            order = self.orderbook.owns[i]
            if order.price == price:
                if order.oid != "":
                    self.cancel(order.oid)

    def cancel_by_type(self, typ=None):
        for i in reversed(range(len(self.orderbook.owns))):
            order = self.orderbook.owns[i]
            if typ is None or typ == order.typ:
                if order.oid != "":
                    self.cancel(order.oid)

    def base2float(self, int_number):
           def base2str(self, int_number):
       
    def base2int(self, float_number):
        
    def quote2float(self, int_number):
            def quote2str(self, int_number):
            def quote2int(self, float_number):
        return int(round(float_number * self.mult_quote))

    def check_connect_ready(self):
        and emit the connect signal if everything is ready"""
        need_no_account = not self.client.secret.know_secret()
        need_no_depth = not self.config.get_bool("bitrex.api", "load_fulldepth")
        need_no_history = not self.config.get_bool("bitrex.api", "load_history")
        need_no_depth = need_no_depth or FORCE_NO_FULLDEPTH
        need_no_history = need_no_history or FORCE_NO_HISTORY
        ready_account = self.ready_info and self.orderbook.ready_owns   and self.ready_idkey...
        if ready_account or need_no_account:
            if self.orderbook.ready_depth or need_no_depth:
                if self.history.ready_history or need_no_history:
                    if self._was_disconnected:
                        self.signal_ready(self, None)
                        self._was_disconnected = False

    def slot_client_connected(self, _sender, _data):
        self.check_connect_ready()

    def slot_fulldepth_processed(self, _sender, _data):
        self.check_connect_ready()

    def slot_fullhistory_processed(self, _sender, _data):
        self.check_connect_ready()

    def slot_owns_initialized(self, _sender, _data):
        self.check_connect_ready()

    def slot_disconnected(self, _sender, _data):
       
        self.ready_info = False
        self.orderbook.ready_owns = False
        self.orderbook.ready_depth = False
        self.history.ready_history = False
        self._was_disconnected = True
        self.signal_disconnected(self, None)
  if (bitrex.api.wallet) and self.bid and self.ask:
            quote_have = bitrex.api.wallet[bitrex.api.curr_quote] + QUOTE_COLD
            base_have = bitrex.api.wallet[bitrex.api.curr_base] + BASE_COLD
            if quote_have == 0 and base_have and self.ask:
                return ((bitrex.api.wallet[bitrex.api.curr_base] / 2) * self.ask) / 2
            elif base_have == 0 and quote_have and self.bid:
                return ((bitrex.api.wallet[bitrex.api.curr_quote] / 2) / self.bid) / 2
        else:
            self.debug('[s]Waiting for price...')
            return False
        return quote_have / base_have

    def get_buy_at_price(self, price):
      
        if price:
            quote_have = self.instance.wallet[self.quote] + QUOTE_COLD
            base_value_then = self.get_base_value(price)
            diff = quote_have - base_value_then
            diff_base = diff / price
            must_buy = diff_base / 2

    def slot_recv(self, dummy_sender, data):
       
        (str_json) = data
        handler = None
        if type(str_json) == dict:
            msg = str_json   was already a dict
        else:
            msg = json.loads(str_json)
        self.msg = msg

class Strategy(strategy.Strategy):
    def __init__(self, instance):
        strategy.Strategy.__init__(self, instance)
        self._waiting = False
        self.bid = 0
        self.ask = 0
        self.simulate = bool(conf['simulate'])
        self.simulate_or_live = 'SIMULATION - ' if self.simulate else 'LIVE - '
        self.base = self.instance.curr_base
        self.quote = self.instance.curr_quote
        self.wallet = False
        self.step_factor = 1 + DISTANCE / 100.0
        self.step_factor_sell = 1 + DISTANCE_SELL / 100.0
        self.temp_halt = False
        self.name = "%s.%s" % (__name__, self.__class__.__name__)
        self.debug("[s]%s%s loaded" % (self.simulate_or_live, self.name))
        self.help()

        if "stamp" in msg:
            delay = time.time() * 1e6 - int(msg["stamp"])
            self.socket_lag = (self.socket_lag * 29 + delay) / 30

        if "op" in msg:
            try:
                msg_op = msg["op"]
                handler = getattr(self, "_on_op_" + msg_op)

            except AttributeError:
                self.debug("slot_recv() ignoring: op=%s" % msg_op)
        else:
            self.debug("slot_recv() ignoring:", msg)

        if handler:
            handler(msg)

    def slot_poll(self, _sender, _data):
        if self.client.secret and self.client.secret.know_secret():
           
    def slot_history_changed(self, _sender, _data):
        
        last_candle = self.history.last_candle()
        if last_candle:
            self.client.history_last_candle = last_candle.tim

    def _on_op_error(self, msg):
        self.debug(" _on_op_error()", msg)

    def _on_op_subscribe(self, msg):
        self.debug(" subscribed channel", msg["channel"])

    def _on_op_ticker(self, msg):
        msg = msg["ticker"]

        bid = msg["bid"]
        ask = msg["ask"]

         self.debug(" tick: %s %s" % (bid, ask))
        self.signal_ticker(self, (bid, ask))

    def _on_op_depth(self, msg):
        msg = msg["depth"]
               typ = msg["type"]
        price = msg["price"]
        volume = msg["volume"]
               self.signal_depth(self, (typ, price, volume))   , total_volume))

    def _on_op_trade(self, msg):
               trade = msg['trade']
        typ = trade["type"]
        price = trade["price"]
        volume = trade["amount"]
        timestamp = int(trade["timestamp"])

        self.debug("trade: %s: %s @ %s" % (
            typ,
            volume,
            price
        ))

        self.signal_trade(self, (timestamp, price, volume, typ, False))   own))

    def _on_op_chat(self, msg):
        msg = msg['msg']
        self.debug("[c]%s %s[%s]: %s" % (
            msg['type'] if msg['type'] != 'trollboxMessage' else ' >',
            msg['user'],
            msg['rep'],
            msg['msg']
        ))

    def _on_op_result(self, msg):
        result = msg["result"]
        reqid = msg["id"]

       
        elif reqid == "info":
            self.wallet = {}
            for currency in result:
                self.wallet[currency] = float(result[currency])

                       self.signal_wallet(self, None)
            self.ready_info = True

            if self.client._wait_for_next_info:
                self.client._wait_for_next_info = False

            self.check_connect_ready()

        elif reqid == "volume":
            self.monthly_volume = result['volume']
            self.currency = result['currency']
            self.trade_fee = result['fee']

        elif reqid == "order_lag":
            lag_usec = result["lag"]
            lag_text = result["lag_text"]
             self.debug(" got order lag: %s" % lag_text)
            self.order_lag = lag_usec
            self.signal_orderlag(self, (lag_usec, lag_text))

        elif "order_add:" in reqid:
            parts = reqid.split(":")
            typ = parts[1]
            price = float(parts[2])
            volume = float(parts[3])
            oid = result
            self.debug(" got ack for order/add:", typ, price, volume, oid)
            self.count_submitted -= 1
            self.orderbook.add_own(Order(price, volume, typ, oid, "pending"))

        elif "order_cancel:" in reqid:
            parts = reqid.split(":")
            oid = parts[1]
            self.debug(" got ack for order/cancel:", oid)

        else:
            self.debug(" _on_op_result() ignoring:", msg)

    def _on_op_private(self, msg):
          private = msg["private"]
        handler = None
        try:
            handler = getattr(self, "_on_op_private_" + private)
        except AttributeError:
            self.debug(" _on_op_private() ignoring: private=%s" % private)
            self.debug(pretty_format(msg))

        if handler:
            handler(msg)

    def _on_op_private_user_order(self, msg):
        order = msg["user_order"]
        oid = order["oid"]

         there exist 3 fundamentally different types of user_order messages,
         they differ in the presence or absence of certain parts of the message

        if "status" in order:
           if order["currency"] == self.curr_quote and order["base"] == self.curr_base:
                volume = order["amount"]
                typ = order["type"]
                status = order["status"]
                if "price" in order:
                     these are limit orders (new or updated)
                    price = order["price"]
                else:
                     these are market orders (new or updated)
                    price = 0
                self.signal_userorder(self, (price, volume, typ, oid, status))

        else:
               def _on_op_private_wallet(self, msg):
        balance = msg["wallet"]["balance"]
        currency = balance["currency"]
        total = balance["value"]
        self.wallet[currency] = total
        self.signal_wallet(self, None)

    def _on_op_private_lag(self, msg):
        self.order_lag = int(msg["lag"]["age"])
        if self.order_lag < 60000000:
            text = "%0.3f s" % (int(self.order_lag / 1000) / 1000.0)
        else:
            text = "%d s" % (int(self.order_lag / 1000000))
        self.signal_orderlag(self, (self.order_lag, text))

    def _on_op_remark(self, msg):

        if "success" in msg and not msg["success"]:
            if msg["message"] == "Invalid call":
                self._on_invalid_call(msg)
            elif msg["message"] == "Order not found":
                self._on_order_not_found(msg)
            elif msg["message"] == "Order amount is too low":
                self._on_order_amount_too_low(msg)
            elif "Too many orders placed" in msg["message"]:
                self._on_too_many_orders(msg)
            else:
                 we should log this, helps with debugging
                self.debug(msg)

    def _on_invalid_call(self, msg):
        """FIXME"""

               if msg["id"] == "info":
            self.debug(" resending private/info")
            self.client.send_signed_call(
                "private/info", {}, "info")

        elif msg["id"] == "orders":
            self.debug(" resending private/orders")
            self.client.send_signed_call(
                "private/orders", {}, "orders")


        else:
            self.debug(" _on_invalid_call() ignoring:", msg)

    def _on_order_not_found(self, msg):
        parts = msg["id"].split(":")
        oid = parts[1]
        self.debug(" got 'Order not found' for", oid)
       
        fakemsg = {"user_order": {"oid": oid, "reason": "requested"}}
        self._on_op_private_user_order(fakemsg)

    def _on_order_amount_too_low(self, _msg):
        self.debug(" Server said: 'Order amount is too low'")
        self.count_submitted -= 1

    def _on_too_many_orders(self, msg):
        self.debug(" Server said: '%s" % msg["message"])
        self.count_submitted -= 1
        self.signal_order_too_fast(self, msg)


class Level:
    def __init__(self, price, volume):
        self.price = price
        self.volume = volume
        self.own_volume = 0

       
        self._cache_total_vol = 0
        self._cache_total_vol_quote = 0

class Order:
    def __init__(self, price, volume, typ, oid="", status=""):
        self.price = price
        self.volume = volume
        self.typ = typ
        self.oid = oid
        self.status = status

class OrderBook(BaseObject):
   

        self.signal_own_removed = Signal()
               self.signal_own_opened = Signal()
               self.signal_own_volume = Signal()
                self.bids = []   list of Level(), lowest ask first
        self.asks = []   list of Level(), highest bid first
        self.owns = []   list of Order(), unordered list

        self.bid = 0
        self.ask = 0
        self.total_bid = 0
        self.total_ask = 0

        self.ready_depth = False
        self.ready_owns = False

        self.last_change_type = None   ("bid", "ask", None) this can be used
        self.last_change_price = 0   for highlighting relative changes
        self.last_change_volume = 0   of orderbook levels in pytrader.py

        self.depth_updated = '-'
        self.orders_updated = '-'

        self._valid_bid_cache = -1    index of bid with valid _cache_total_vol
        self._valid_ask_cache = -1    index of ask with valid _cache_total_vol

        bitrex.api.signal_ticker.connect(self.slot_ticker)
        bitrex.api.signal_depth.connect(self.slot_depth)
        bitrex.api.signal_trade.connect(self.slot_trade)
        bitrex.api.signal_userorder.connect(self.slot_user_order)
        bitrex.api.signal_fulldepth.connect(self.slot_fulldepth)

    def slot_ticker(self, dummy_sender, data):
        (bid, ask) = data
        self.bid = bid
        self.ask = ask
        self.last_change_type = None
        self.last_change_price = 0
        self.last_change_volume = 0
        self._repair_crossed_asks(ask)
        self._repair_crossed_bids(bid)
        self.signal_changed(self, None)

conf.setdefault('simulate', True)
conf.setdefault('distance', 5)
conf.setdefault('distance_sell', 5)
conf.setdefault('quote_cold', 0)
conf.setdefault('base_cold', 0)
conf.setdefault('quote_limit', 0)
conf.setdefault('base_limit', 0)
conf.setdefault('marker', 9)
conf.setdefault('compensate_fees', True)
conf.setdefault('correction_margin', 1)
conf.setdefault('simulate_quote', 15)
conf.setdefault('simulate_base', 5000)
conf.setdefault('simulate_fee', 0.05)
with open('balancer.conf', 'w') as configfile:
    json.dump(conf, configfile, indent=2)


    def slot_depth(self, dummy_sender, data):
        (typ, price, total_vol) = data
        if self._update_book(typ, price, total_vol):
            self.signal_changed(self, None)

    def slot_trade(self, dummy_sender, data):
       
        (dummy_date, price, volume, typ, own) = data
        if own:
             nothing special to do here (yet), there will also be
             separate user_order messages to update my owns list
             and a copy of this trade message in the public channel
            pass
        else:
             we update the orderbook. We could also wait for the depth
             message but we update the orderbook immediately.
            voldiff = -volume
            if typ == "bid":   typ=bid means an ask order was filled
                self._repair_crossed_asks(price)
                if len(self.asks):
                    if self.asks[0].price == price:
                        self.asks[0].volume -= volume
                        if self.asks[0].volume <= 0:
                            voldiff -= self.asks[0].volume
                            self.asks.pop(0)
                        self.last_change_type = "ask"   the asks have changed
                        self.last_change_price = price
                        self.last_change_volume = voldiff
                        self._update_total_ask(voldiff)
                        self._valid_ask_cache = -1
                if len(self.asks):
                    self.ask = self.asks[0].price

            if typ == "ask":   typ=ask means a bid order was filled
                self._repair_crossed_bids(price)
                if len(self.bids):
                    if self.bids[0].price == price:
                        self.bids[0].volume -= volume
                        if self.bids[0].volume <= 0:
                            voldiff -= self.bids[0].volume
                            self.bids.pop(0)
                        self.last_change_type = "bid"   the bids have changed
                        self.last_change_price = price
                        self.last_change_volume = voldiff
                        self._update_total_bid(voldiff, price)
                        self._valid_bid_cache = -1
                if len(self.bids):
                    self.bid = self.bids[0].price

        self.signal_changed(self, None)

    def slot_user_order(self, dummy_sender, data):
       
        (price, volume, typ, oid, status) = data
        found = False
        removed = False   was the order removed?
        opened = False   did the order change from 'post-pending' to 'open'"?
        voldiff = 0      did the order volume change (full or partial fill)
        if "executing" in status:
             don't need this status at all
            return
        if "post-pending" in status:
             don't need this status at all
            return
        if "removed" in status:
            for i in range(len(self.owns)):
                if self.owns[i].oid == oid:
                    order = self.owns[i]
                    if order.price == 0:
                        if "passive" in status:
                             ignore it, the correct one with
                             "active" will follow soon
                            return

                    self.debug(
                        " removing order %s " % oid,
                        "price:", order.price,
                        "type:", order.typ)

                     remove it from owns...
                    self.owns.pop(i)

                     ...and update own volume cache in the bids or asks
                    self._update_level_own_volume(
                        order.typ,
                        order.price,
                        self.get_own_volume_at(order.price, order.typ)
                    )
                    removed = True
                    break
        else:
            for order in self.owns:
                if order.oid == oid:
                    found = True
                    self.debug(
                        " updating order %s " % oid,
                        "volume:", volume,
                        "status:", status)
                    voldiff = volume - order.volume
                    opened = (order.status != "open" and status == "open")
                    order.volume = volume
                    order.status = status
                    break

            if not found:
              
            self._update_level_own_volume(
                typ, price, self.get_own_volume_at(price, typ))

       
        if removed:
            reason = self.bitrex.api.msg["user_order"]["reason"]
            self.signal_own_removed(self, (order, reason))
        if opened:
            self.signal_own_opened(self, (order))
        if voldiff:
            self.signal_own_volume(self, (order, voldiff))
        self.signal_changed(self, None)
        self.signal_owns_changed(self, None)

    def slot_fulldepth(self, dummy_sender, data):
        (depth) = data
         self.debug(" got full depth, updating orderbook...")
        self.bids = []
        self.asks = []
        self.total_ask = 0
        self.total_bid = 0
        if "error" in depth and depth['error']:
            self.debug(" ", depth["error"])
            return
        for order in depth["data"]["asks"]:
            price = order["price"]
            volume = order["amount"]
            self._update_total_ask(volume)
            self.asks.append(Level(price, volume))
        for order in depth["data"]["bids"]:
            price = order["price"]
            volume = order["amount"]
            self._update_total_bid(volume, price)
            self.bids.insert(0, Level(price, volume))

         update own volume cache
        for order in self.owns:
            self._update_level_own_volume(
                order.typ, order.price, self.get_own_volume_at(order.price, order.typ))

        if len(self.bids):
            self.bid = self.bids[0].price
        if len(self.asks):
            self.ask = self.asks[0].price

        self._valid_ask_cache = -1
        self._valid_bid_cache = -1
        self.ready_depth = True
        self.depth_updated = time.strftime("%Y-%m-%d %H:%M:%S")
        self.signal_fulldepth_processed(self, None)
        self.signal_changed(self, None)

    def _repair_crossed_bids(self, bid):
               while len(self.bids) and self.bids[0].price > bid:
            price = self.bids[0].price
            volume = self.bids[0].volume
            self._update_total_bid(-volume, price)
            self.bids.pop(0)
            self._valid_bid_cache = -1
             self.debug(" repaired bid")

    def _repair_crossed_asks(self, ask):
               while len(self.asks) and self.asks[0].price < ask:
            volume = self.asks[0].volume
            self._update_total_ask(-volume)
            self.asks.pop(0)
            self._valid_ask_cache = -1
             self.debug(" repaired ask")

    def _update_book(self, typ, price, total_vol):
       
        (lst, index, level) = self._find_level(typ, price)
        if total_vol == 0:
            if level is None:
                return False
            else:
                voldiff = -level.volume
                lst.pop(index)
        else:
            if level is None:
                voldiff = total_vol
                level = Level(price, total_vol)
                lst.insert(index, level)
            else:
                voldiff = total_vol - level.volume
                if voldiff == 0:
                    return False
                level.volume = total_vol

         now keep all the other stuff in sync with it
        self.last_change_type = typ
        self.last_change_price = price
        self.last_change_volume = voldiff
        if typ == "ask":
            self._update_total_ask(voldiff)
            if len(self.asks):
                self.ask = self.asks[0].price
            self._valid_ask_cache = min(self._valid_ask_cache, index - 1)
        else:
            self._update_total_bid(voldiff, price)
            if len(self.bids):
                self.bid = self.bids[0].price
            self._valid_bid_cache = min(self._valid_bid_cache, index - 1)

        return True

    def _update_total_ask(self, volume):
        self.total_ask += volume

    def _update_total_bid(self, volume, price):
        self.total_bid += volume * price

    def _update_level_own_volume(self, typ, price, own_volume):

        if price == 0:
           

        (index, level) = self._find_level_or_insert_new(typ, price)
        if level.volume == 0 and own_volume == 0:
            if typ == "ask":
                self.asks.pop(index)
            else:
                self.bids.pop(index)
        else:
            level.own_volume = own_volume

    def _find_level(self, typ, price):
       
        lst = {"ask": self.asks, "bid": self.bids}[typ]
        comp = {"ask": lambda x, y: x < y, "bid": lambda x, y: x > y}[typ]
        low = 0
        high = len(lst)

         binary search
        while low < high:
            mid = (low + high) // 2
            midval = lst[mid].price
            if comp(midval, price):
                low = mid + 1
            elif comp(price, midval):
                high = mid
            else:
                return (lst, mid, lst[mid])

         not found, return insertion point (index of next higher level)
        return (lst, high, None)

    def _find_level_or_insert_new(self, typ, price):
                (lst, index, level) = self._find_level(typ, price)
        if level:
            return (index, level)

         no exact match found, create new Level() and insert
        level = Level(price, 0)
        lst.insert(index, level)

         invalidate the total volume cache at and beyond this level
        if typ == "ask":
            self._valid_ask_cache = min(self._valid_ask_cache, index - 1)
        else:
            self._valid_bid_cache = min(self._valid_bid_cache, index - 1)

        return (index, level)

    def get_own_volume_at(self, price, typ=None):
               volume = 0
        for order in self.owns:
            if order.price == price and (not typ or typ == order.typ):
                volume += order.volume
        return volume

    def have_own_oid(self, oid):
        for order in self.owns:
            if order.oid == oid:
                return True
        return False

    def get_total_up_to(self, price, is_ask):
        
        if is_ask:
            lst = self.asks
            known_level = self._valid_ask_cache
            comp = lambda x, y: x < y
        else:
            lst = self.bids
            known_level = self._valid_bid_cache
            comp = lambda x, y: x > y

       
        low = 0
        high = len(lst)
        while low < high:
            mid = (low + high) // 2
            midval = lst[mid].price
            if comp(midval, price):
                low = mid + 1
            elif comp(price, midval):
                high = mid
            else:
                break
        if comp(price, midval):
            needed_level = mid - 1
        else:
            needed_level = mid

       
        if known_level == -1:
            total = 0
            total_quote = 0
        else:
            total = lst[known_level]._cache_total_vol
            total_quote = lst[known_level]._cache_total_vol_quote

        for i in range(known_level, needed_level):
            that = lst[i + 1]
            total += that.volume
            total_quote += that.volume * that.price   / mult_base
            that._cache_total_vol = total
            that._cache_total_vol_quote = total_quote

        if is_ask:
            self._valid_ask_cache = needed_level
        else:
            self._valid_bid_cache = needed_level

        return (total, total_quote)

    def init_own(self, own_orders):
        
class Strategy(strategy.Strategy):

    def __init__(self, bitrex.api):
        strategy.Strategy.__init__(self, bitrex.api)
        self.signal_debug.connect(bitrex.api.signal_debug)
        bitrex.api.signal_keypress.connect(self.slot_keypress)
        # bitrex.api.signal_strategy_unload.connect(self.slot_before_unload)
        bitrex.api.signal_ticker.connect(self.slot_tick)
        bitrex.api.signal_depth.connect(self.slot_depth)
        bitrex.api.signal_trade.connect(self.slot_trade)
        bitrex.api.signal_userorder.connect(self.slot_userorder)
        bitrex.api.orderbook.signal_owns_changed.connect(self.slot_owns_changed)
        bitrex.api.signal_wallet.connect(self.slot_wallet_changed)
        self.bitrex.api = bitrex.api
        self.name = "%s.%s" % (__name__, self.__class__.__name__)
        self.debug("[s]%s%s loaded" % (simulate_or_live, self.name))
        self.debug("[s]Press 'b' to see Buy objective")
        # get existing orders for later decision making
        self.existingorders = []
        for order in self.bitrex.api.orderbook.owns:
            self.existingorders.append(order.oid)


        self.owns = []

        for level in self.bids + self.asks:
            level.own_volume = 0

        if own_orders:
            for order in own_orders:
                if order["currency"] == self.bitrex.api.curr_quote and order["base"] == self.bitrex.api.curr_base:
                    self._add_own(Order(
                        order["price"],
                        order["amount"],
                        order["type"],
                        order["oid"],
                        order["status"]
                    ))

        self.orders_updated = time.strftime("%Y-%m-%d %H:%M:%S")
        self.ready_owns = True
        self.signal_changed(self, None)
        self.signal_owns_initialized(self, None)
        self.signal_owns_changed(self, None)

    def add_own(self, order):
        
        if not self.have_own_oid(order.oid):
            self.debug(" adding order:", order.typ, order.price, order.volume, order.oid)
            self._add_own(order)
            self.signal_own_added(self, (order))
            self.signal_changed(self, None)
            self.signal_owns_changed(self, None)

    def _add_own(self, order):
        if not self.have_own_oid(order.oid):
            self.owns.append(order)

             update own volume in that level:
            self._update_level_own_volume(
                order.typ,
                order.price,
                self.get_own_volume_at(order.price, order.typ)
            )

def menu():
    try:
        uid = subprocess.os.getuid()
        if uid:
            print 'Please use sudo or use root!'
            exit(10)
        #subprocess.call('iptables -F',shell='/bin/sh')
        while True:
            prompt = raw_input('middlebox > ').strip()
            if prompt in ['help','add rule', 'del rule', 'list rules', 'exit', 'clear']:
                if prompt == 'help' :
                    show_help()
                elif prompt == 'add rule':
                    protocol,port,rule = take_values()
                    add_rule(protocol,port,rule)
                elif prompt == 'del rule':
                    protocol,port,rule = take_values()
                    delete_rule(protocol,port,rule)
                elif prompt == 'list rules':
                    list_rules()
                elif prompt == 'exit':
                    exit(0)
                elif prompt == 'clear':
                    subprocess.call('clear')
                else :
                    pass
            else: 
                print 'type help for options.'
    # except block to handle keyboard interrupt like Ctrl+C and Ctrl+D.
    except (KeyboardInterrupt, SystemExit, EOFError):
        print ''
        print 'Bye'

def take_values() :
    while True:
        protocol = raw_input("Protocol > ").strip().lower()
        # Only icmp tcp and udp protocols supported.
        if protocol not in ['icmp','tcp','udp']:
            print 'please enter only icmp , tcp or udp'
        else:
            if protocol not in ["icmp"]:
                while True:
                    try:
                        port = raw_input("Port > ").strip()
                        test_port = int(port)
                        if test_port < 0 or test_port > 65535:
                            print 'port range 0-65535'
                        else:
                            break
                    except ValueError:
                        print 'Port should be int value'
            else: 
                # There is no need for port if the protocol is icmp
                port = None
            while True:
                rule = raw_input("ACCEPT/REJECT/DROP > ").strip().upper()
                if rule not in ['ACCEPT','REJECT','DROP']:
                    print 'ACCEPT/REJECT/DROP'
                else:
                    break
            return(protocol,port,rule)

def add_rule(protocol, port, rule):
    if port:
        chk = 'iptables -C FORWARD -p %s --dport %s -j %s'%(protocol, port, rule)
    else:
        chk = 'iptables -C FORWARD -p %s -j %s'%(protocol, rule)
    # subprocess to spawn a new process to check the presence of firewall rule using iptabes.
    ck = subprocess.Popen(chk, shell='/bin/sh',stderr = subprocess.PIPE, stdout = subprocess.PIPE)
    ck.communicate()
    if ck.returncode :
        print 'Applying rule'
        # Function call to apply a firewall rule.
        apply_rule(protocol, port, rule)
    else:
        print 'Deleting rule'
        # Function call to delete a rule.
        delete_rule(protocol, port, rule)
        apply_rule(protocol, port, rule)

def apply_rule(protocol, port, rule) :
    if port:
        cmd = 'iptables -I FORWARD -p %s --dport %s -j %s'%(protocol, port, rule)
    else: 
        cmd = 'iptables -I FORWARD -p %s -j %s'%(protocol, rule)
    # subprocess to spawn a new process to add firewall rule using iptables.
    pr = subprocess.Popen(cmd, shell='/bin/sh',stderr = subprocess.PIPE, stdout = subprocess.PIPE)
    pr.communicate()
    if pr.returncode :
        print "Error applying rule"
    else:
        print "Rule applied"

def delete_rule(protocol, port, rule):
    if port:
        delcmd = 'iptables -D FORWARD -p %s --dport %s -j %s'%(protocol, port, rule)
    else:
        delcmd = 'iptables -D FORWARD -p %s -j %s'%(protocol, rule)
    delc = subprocess.Popen(delcmd, shell='/bin/sh',stderr = subprocess.PIPE, stdout = subprocess.PIPE)
    msg = delc.communicate()[1].strip('\n')
    if delc.returncode  :
        print 'No such rule'
    else:
        print "Rule deleted"

def show_help():
    print 'help        : display this message'
    print 'add rule    : to add a rule to the routing table'
    print 'del rule    : to delete a rule from the routing table'
    print 'list rules  : to list the current routing table'
    print 'exit        : to get out of this prompt'

def list_rules():
    cmd = 'iptables -nvL FORWARD'
    list_rule = subprocess.Popen(cmd, shell='/bin/sh',stderr = subprocess.PIPE, stdout = subprocess.PIPE)
    rule_list = list_rule.communicate()[0].split('\n')
    for i in rule_list:
        print i

menu()
