"""
This file contains functions to stream data
Coded by Tyler Bowers
Github: https://github.com/tylerebowers/Schwab-API-Python
"""

import json
import atexit
import asyncio
import datetime
import threading
import websockets
from time import sleep
import websockets.exceptions


class Stream:

    def __init__(self, client):
        """
        Initialize the stream object to stream data from Schwab Streamer
        :param client: Client object
        :type client: Client
        """
        self._websocket = None          # the websocket
        self._streamer_info = None      # streamer info from api call
        self._request_id = 0            # a counter for the request id
        self.active = False             # whether the stream is active
        self._thread = None             # the thread that runs the stream
        self._client = client           # so we can get streamer info
        self.subscriptions = {}         # a dictionary of subscriptions

        # register atexit to stop the stream (if active)
        def stop_atexit():
            if self.active:
                self.stop()
        atexit.register(stop_atexit)


    async def _start_streamer(self, receiver_func=print, **kwargs):
        """
        Start the streamer
        :param receiver_func: function to call when data is received
        :type receiver_func: function
        """
        # get streamer info
        response = self._client.preferences()
        if response.ok:
            self._streamer_info = response.json().get('streamerInfo', None)[0]
        else:
            print("[Schwabdev] Could not get streamerInfo")
            return

        # start the stream
        start_time = datetime.datetime.now(datetime.timezone.utc)
        while True:
            try:
                start_time = datetime.datetime.now(datetime.timezone.utc)
                if self._client.verbose: print("[Schwabdev] Connecting to streaming server...")
                async with websockets.connect(self._streamer_info.get('streamerSocketUrl'), ping_interval=None) as self._websocket:
                    if self._client.verbose: print("[Schwabdev] Connected to streaming server.")
                    # send login payload
                    login_payload = self.basic_request(service="ADMIN",
                                                       command="LOGIN",
                                                       parameters={"Authorization": self._client.access_token,
                                                                   "SchwabClientChannel": self._streamer_info.get("schwabClientChannel"),
                                                                   "SchwabClientFunctionId": self._streamer_info.get("schwabClientFunctionId")})
                    await self._websocket.send(json.dumps(login_payload))
                    receiver_func(await self._websocket.recv(), **kwargs)
                    self.active = True

                    # send subscriptions
                    for service, subs in self.subscriptions.items():
                        reqs = []
                        for key, fields in subs.items():
                            reqs.append(self.basic_request(service=service,
                                                           command="ADD",
                                                           parameters={"keys": key,
                                                                       "fields": Stream._list_to_string(fields)}))
                        if reqs:
                            await self._websocket.send(json.dumps({"requests": reqs}))
                            receiver_func(await self._websocket.recv(), **kwargs)

                    # main listener loop
                    while True:
                        receiver_func(await self._websocket.recv(), **kwargs)

            except Exception as e:
                self.active = False
                if e is websockets.exceptions.ConnectionClosedOK or str(e) == "received 1000 (OK); then sent 1000 (OK)":  # catch logout request
                    if self._client.verbose: print("[Schwabdev] Stream connection closed.")
                    break
                elif e is websockets.exceptions.ConnectionClosedError or str(e) == "no close frame received or sent":  # catch no subscriptions kick
                    print(f"[Schwabdev] Stream connection closed (likely no subscriptions): {e}")
                    break
                elif (datetime.datetime.now(datetime.timezone.utc) - start_time).seconds <= 90:
                    print(f"[Schwabdev] Stream has crashed within 90 seconds ({e}), likely no subscriptions, invalid login, or lost connection (not restarting).")
                    break
                else: # stream has quit unexpectedly, try to reconnect
                    print(f"[Schwabdev] Stream connection lost to server ({e}), reconnecting...")

    def start(self, receiver=print, daemon: bool = True, **kwargs):
        """
        Start the stream
        :param receiver: function to call when data is received
        :type receiver: function
        :param daemon: whether to run the thread in the background (as a daemon)
        :type daemon: bool
        """
        if not self.active:
            def _start_async():
                asyncio.run(self._start_streamer(receiver, **kwargs))

            self._thread = threading.Thread(target=_start_async, daemon=daemon)
            self._thread.start()
            # if the thread does not start in time then the main program may close before the streamer starts
        else:
            if self._client.verbose: print("[Schwabdev] Stream already active.")

    def start_auto(self, receiver=print, after_hours=False, pre_hours=False, daemon: bool = True, **kwargs):
        """
        Start the stream automatically at market open and close, will NOT erase subscriptions
        :param receiver: function to call when data is received
        :type receiver: function
        :param after_hours: include after hours trading
        :type after_hours: bool
        :param pre_hours: include pre hours trading
        :type pre_hours: bool
        """
        start = datetime.time(13, 29, 0, tzinfo=datetime.timezone.utc)  # market opens at 9:30 ET
        end = datetime.time(20, 0, 0, tzinfo=datetime.timezone.utc)  # market closes at 4:00 ET
        if pre_hours:
            start = datetime.time(10, 59, 0, tzinfo=datetime.timezone.utc)
        if after_hours:
            end = datetime.time.max.replace(tzinfo=datetime.timezone.utc) # 23:59:59:999999
        def checker():

            while True:
                now = datetime.datetime.now(datetime.timezone.utc)
                in_hours = (start <= now.time().replace(tzinfo=datetime.timezone.utc) <= end) and (0 <= now.weekday() <= 4)
                if in_hours and not self.active:
                    if len(self.subscriptions) == 0:
                        if self._client.verbose: print("[Schwabdev] No subscriptions, starting stream anyways.")
                    self.start(receiver=receiver, daemon=daemon, **kwargs)
                elif not in_hours and self.active:
                    if self._client.verbose: print("[Schwabdev] Stopping Stream.")
                    self.stop(clear_subscriptions=False)
                sleep(30)

        threading.Thread(target=checker, daemon=daemon).start()

        if not start <= datetime.datetime.now(datetime.timezone.utc).time().replace(tzinfo=datetime.timezone.utc) <= end:
            print("[Schwabdev] Stream was started outside of active hours and will launch when in hours.")

    def _record_request(self, request: dict):
        """
        Record the request into self.subscriptions (for the event of crashes)
        :param request: request
        :type request: dict
        """
        def str_to_list(st):
            if type(st) is str: return st.split(",")
            elif type(st) is list: return st
        service = request.get("service", None)
        command = request.get("command", None)
        parameters = request.get("parameters", None)
        if parameters is not None:
            keys = str_to_list(parameters.get("keys", []))
            fields = str_to_list(parameters.get("fields", []))
            # add service to subscriptions if not already there
            if service not in self.subscriptions:
                self.subscriptions[service] = {}
            if command == "ADD":
                for key in keys:
                    if key not in self.subscriptions[service]:
                        self.subscriptions[service][key] = fields
                    else:
                        self.subscriptions[service][key] = list(set(fields) | set(self.subscriptions[service][key]))
            elif command == "SUBS":
                self.subscriptions[service] = {}
                for key in keys:
                    self.subscriptions[service][key] = fields
            elif command == "UNSUBS":
                for key in keys:
                    if key in self.subscriptions[service]:
                        self.subscriptions[service].pop(key)
            elif command == "VIEW":  # not sure if this is even working on Schwab's end :/
                for key in self.subscriptions[service].keys():
                    self.subscriptions[service][key] = fields



    def send(self, requests: list | dict):
        """
        Send a request to the stream
        :param requests: list of requests or a single request
        :type requests: list | dict
        """
        # an async function to send the request
        async def _send(to_send):
            await self._websocket.send(to_send)

        # make sure requests is a list
        if type(requests) is not list:
            requests = [requests]

        # add requests to list of subscriptions
        for request in requests:
            self._record_request(request)

        # send the request if the stream is active, queue otherwise
        if self.active:
            to_send = json.dumps({"requests": requests})
            asyncio.run(_send(to_send))
        else:
            if self._client.verbose: print("[Schwabdev] Stream is not active, request queued.")


    async def send_async(self, requests: list | dict):
        """
        Send an async (must be awaited) request to the stream (functionally equivalent to send)
        :param requests: list of requests or a single request
        :type requests: list | dict
        """

        # make sure requests is a list
        if type(requests) is not list:
            requests = [requests]

        # add requests to list of subscriptions
        for request in requests:
            self._record_request(request)

        # send the request if the stream is active, queue otherwise
        if self.active:
            to_send = json.dumps({"requests": requests})
            await self._websocket.send(to_send)
        else:
            if self._client.verbose: print("[Schwabdev] Stream is not active, request queued.")


    def stop(self, clear_subscriptions: bool = True):
        """
        Stop the stream
        :param clear_subscriptions: clear records
        :type clear_subscriptions: bool
        """
        if clear_subscriptions:
            self.subscriptions = {}
        self._request_id += 1
        self.send(self.basic_request(service="ADMIN", command="LOGOUT"))
        self.active = False

    def basic_request(self, service: str, command: str, parameters: dict = None):
        """
        Create a basic request (all requests follow this format)
        :param service: service to use
        :type service: str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW"|"LOGIN"|"LOGOUT")
        :type command: str
        :param parameters: parameters to use
        :type parameters: dict
        :return: stream request
        :rtype: dict
        """
        if self._streamer_info is None:
            response = self._client.preferences()
            if response.ok:
                self._streamer_info = response.json().get('streamerInfo', None)[0]
            else:
                print("[Schwabdev] Could not use/get streamerInfo")
                return {}

        # remove None parameters
        if parameters is not None:
            for key in parameters.keys():
                if parameters[key] is None: del parameters[key]

        self._request_id += 1
        request = {"service": service.upper(),
                   "command": command.upper(),
                   "requestid": self._request_id,
                   "SchwabClientCustomerId": self._streamer_info.get("schwabClientCustomerId"),
                   "SchwabClientCorrelId": self._streamer_info.get("schwabClientCorrelId")}
        if parameters is not None and len(parameters) > 0: request["parameters"] = parameters
        return request

    @staticmethod
    def _list_to_string(ls: list | str):
        """
        Convert a list to a string (e.g. [1, "B", 3] -> "1,B,3"), or passthrough if already a string
        :param ls: list to convert
        :type ls: list | str
        :return: converted string
        :rtype: str
        """
        if type(ls) is str: return ls
        elif type(ls) is list: return ",".join(map(str, ls))

    def level_one_equities(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Level one equities
        :param keys: list of keys to use (e.g. ["AMD", "INTC"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("LEVELONE_EQUITIES", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def level_one_options(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Level one options, key format: [Underlying Symbol (6 characters including spaces) | Expiration (6 characters) | Call/Put (1 character) | Strike Price (5+3=8 characters)]
        :param keys: list of keys to use (e.g. ["GOOG  240809C00095000", "AAPL  240517P00190000"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("LEVELONE_OPTIONS", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def level_one_futures(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Level one futures, key format: '/' + 'root symbol' + 'month code' + 'year code'; month code is 1 character: (F: Jan, G: Feb, H: Mar, J: Apr, K: May, M: Jun, N: Jul, Q: Aug, U: Sep, V: Oct, X: Nov, Z: Dec), year code is 2 characters (i.e. 2024 = 24)
        :param keys: list of keys to use (e.g. ["/ESF24", "/GCG24"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("LEVELONE_FUTURES", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def level_one_futures_options(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Level one futures options, key format: '.' + '/' + 'root symbol' + 'month code' + 'year code' + 'Call/Put code' + 'Strike Price'
        :param keys: list of keys to use (e.g. ["./OZCZ23C565"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("LEVELONE_FUTURES_OPTIONS", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def level_one_forex(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Level one forex, key format: 'from currency' + '/' + 'to currency'
        :param keys: list of keys to use (e.g. ["EUR/USD", "JPY/USD"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("LEVELONE_FOREX", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def nyse_book(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        NYSE book orders
        :param keys: list of keys to use (e.g. ["NIO", "F"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("NYSE_BOOK", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def nasdaq_book(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        NASDAQ book orders
        :param keys: list of keys to use (e.g. ["AMD", "CRWD"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("NASDAQ_BOOK", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def options_book(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Options book orders
        :param keys: list of keys to use (e.g. ["GOOG  240809C00095000", "AAPL  240517P00190000"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("OPTIONS_BOOK", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def chart_equity(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Chart equity
        :param keys: list of keys to use (e.g. ["GOOG", "AAPL"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("CHART_EQUITY", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def chart_futures(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Chart futures, key format: '/' + 'root symbol' + 'month code' + 'year code'; month code is 1 character: (F: Jan, G: Feb, H: Mar, J: Apr, K: May, M: Jun, N: Jul, Q: Aug, U: Sep, V: Oct, X: Nov, Z: Dec), year code is 2 characters (i.e. 2024 = 24)
        :param keys: list of keys to use (e.g. ["/ESF24", "/GCG24"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("CHART_FUTURES", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def screener_equity(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Screener equity, key format: (PREFIX)_(SORTFIELD)_(FREQUENCY); Prefix: ($COMPX, $DJI, $SPX.X, INDEX_AL, NYSE, NASDAQ, OTCBB, EQUITY_ALL); Sortfield: (VOLUME, TRADES, PERCENT_CHANGE_UP, PERCENT_CHANGE_DOWN, AVERAGE_PERCENT_VOLUME), Frequency: (0 (all day), 1, 5, 10, 30 60)
        :param keys: list of keys to use (e.g. ["$DJI_PERCENT_CHANGE_UP_60", "NASDAQ_VOLUME_30"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("SCREENER_EQUITY", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def screener_options(self, keys: str | list, fields: str | list, command: str = "ADD") -> dict:
        """
        Screener option key format: (PREFIX)_(SORTFIELD)_(FREQUENCY); Prefix: (OPTION_PUT, OPTION_CALL, OPTION_ALL); Sortfield: (VOLUME, TRADES, PERCENT_CHANGE_UP, PERCENT_CHANGE_DOWN, AVERAGE_PERCENT_VOLUME), Frequency: (0 (all day), 1, 5, 10, 30 60)
        :param keys: list of keys to use (e.g. ["OPTION_PUT_PERCENT_CHANGE_UP_60", "OPTION_CALL_TRADES_30"])
        :type keys: list | str
        :param fields: list of fields to use
        :type fields: list | str
        :param command: command to use ("SUBS"|"ADD"|"UNSUBS"|"VIEW")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("SCREENER_OPTION", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})

    def account_activity(self, keys="Account Activity", fields="0,1,2,3", command: str = "SUBS") -> dict:
        """
        Account activity
        :param keys: list of keys to use (e.g. ["Account Activity"])
        :type keys: list | str
        :param fields: list of fields to use (e.g. ["0,1,2,3"])
        :type fields: list | str
        :param command: command to use ("SUBS"|"UNSUBS")
        :type command: str
        :return: stream request
        :rtype: dict
        """
        return self.basic_request("ACCT_ACTIVITY", command, parameters={"keys": Stream._list_to_string(keys), "fields": Stream._list_to_string(fields)})
