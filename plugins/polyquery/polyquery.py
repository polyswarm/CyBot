# !vtquery is used for Querying the VirusTotal API
import asyncio
import os, requests, json, re
from asyncio.events import AbstractEventLoop

from errbot import BotPlugin, botcmd, arg_botcmd
from polyswarm_api import PolyswarmAPI
from polyswarm_api.formatting import PSResultFormatter, PSDownloadResultFormatter, PSSearchResultFormatter, PSHuntResultFormatter, \
    PSHuntSubmissionFormatter, PSStreamFormatter
from threading import Thread

from polyswarm_api.result import PolyswarmSearchResults

api_key = os.getenv("POLYSWARM_API_KEY")

class MyEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        def start_loop(loop):
            asyncio.set_event_loop(loop)
            loop.run_forever()
        self.t = Thread(target=start_loop, args=(self.loop,))
        super().__init__()

    def new_event_loop(self) -> AbstractEventLoop:
        return self.loop

    def get_event_loop(self):
        """Get the event loop.

        This may be None or an instance of EventLoop.
        """
        return self.loop

class PolySwarmResultsParser(object):
    def __init__(self, raw_results):
        self.raw_results = raw_results


    def scan_results(self):
        pass

class PolyQuery(BotPlugin):
    def activate(self) -> None:
        asyncio.set_event_loop_policy(MyEventLoopPolicy())
        super().activate()

    @arg_botcmd('hash', type=str, template="hash_search")  # flags a command
    def poly_search(self, msg, hash=None):
        # in this thread

        api = PolyswarmAPI(api_key)

        r = api.search_hash(hash)

        results_obj = PolyswarmSearchResults(r)
        latest_bounty_result = results_obj.get_latest_bounty_with_assertions()

        assertions = latest_bounty_result.get_file_assertions()

        # todo weight who thinks what about the file
        return {"latest_bounty_result": latest_bounty_result, "assertions": assertions, "defang_permalink": latest_bounty_result.permalink.replace("http", "hxxp")}

    @arg_botcmd('imphash', type=str)
    def poly_imphash(self, msg, imphash=None):
        if not re.findall(r"(^[a-fA-F\d]{32})", imphash):
            return "Invalid imphash"

        api = PolyswarmAPI(api_key)

        r = api.search_query("pefile.imphash={}".format(imphash))
        return PSSearchResultFormatter(r, color=False)
