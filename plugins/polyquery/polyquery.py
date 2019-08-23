# !vtquery is used for Querying the VirusTotal API
import asyncio
import hashlib
import os, requests, json, re
import shutil
import tempfile
import traceback
from asyncio.events import AbstractEventLoop
from io import BytesIO

import requests

from errbot import BotPlugin, botcmd, arg_botcmd, Message
from errbot.backends.base import Stream
from polyswarm_api import PolyswarmAPI, select_hash_type_by_hash_value

from polyswarm_api.formatting import PSResultFormatter, PSDownloadResultFormatter, PSSearchResultFormatter, \
    PSHuntResultFormatter, \
    PSHuntSubmissionFormatter, PSStreamFormatter
from threading import Thread

from polyswarm_api.result import PolyswarmSearchResults, PolySwarmBaseResult, BountyResult
import pyminizip

INFECTED_PW_FOR_ZIP = "infected"

INVALID_HASH_MSG = "Invalid hash (try md5, sha256, or sha1)"

api_key = os.getenv("POLYSWARM_API_KEY")


class ErrBotManyThreadsEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
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


class PolyQuery(BotPlugin):
    def activate(self) -> None:
        asyncio.set_event_loop_policy(ErrBotManyThreadsEventLoopPolicy())
        super().activate()

    def _api_factory(self):
        api = PolyswarmAPI(api_key)
        return api

    @arg_botcmd('hash', type=str, template="hash_search")  # flags a command
    def poly_search(self, msg, hash=None):
        # in this thread
        hash_type_str = select_hash_type_by_hash_value(hash)
        if hash_type_str is None:
            return {"hash": hash, "error": INVALID_HASH_MSG}

        api = self._api_factory()

        r = api.search_hash(hash, hash_type=hash_type_str)

        results_obj = PolyswarmSearchResults(r)
        latest_bounty_result = results_obj.get_latest_bounty_with_assertions()
        if not latest_bounty_result:
            return {"latest_bounty_result": latest_bounty_result, "hash": hash}

        assertions = latest_bounty_result.get_file_assertions()

        # todo weight who thinks what about the file
        return {"latest_bounty_result": latest_bounty_result, "search_results": results_obj, "assertions": assertions,
                "defang_permalink": latest_bounty_result.permalink.replace("http", "hxxp")}

    @arg_botcmd("hash", type=str)
    def poly_download(self, msg, hash=None):
        hash_type_str = select_hash_type_by_hash_value(hash)
        if hash_type_str is None:
            return INVALID_HASH_MSG

        api = self._api_factory()
        tmpdir = tempfile.mkdtemp(suffix=".polyswarm")
        resp_msg = "Unable to download file"
        try:
            jr = api.download_file(hash, tmpdir, hash_type=hash_type_str, with_metadata=True)

            r = PolySwarmBaseResult(jr)

            if r.status_ok:
                resp_msg = "Unable to zip file"
                zip_file_name = "{0}.zip".format(hash)
                zip_path = os.path.join(tmpdir, zip_file_name)
                files_to_zip = [hash, "{}.json".format(hash)]
                pyminizip.compress_multiple([os.path.join(tmpdir, f) for f in files_to_zip], files_to_zip, zip_path,
                                            INFECTED_PW_FOR_ZIP, 5)
                resp_msg = "Unable to upload file"
                self.send_stream_request(msg.frm, open(zip_path, 'rb'), name=zip_file_name,
                                         stream_type="application/zip")
                resp_msg = "File ready (password: {}).".format(INFECTED_PW_FOR_ZIP)
            else:
                resp_msg = r.reason
        except Exception as e:
            traceback.print_exc()
        finally:
            shutil.rmtree(tmpdir)
        return resp_msg

    @arg_botcmd('imphash', type=str)
    def poly_imphash(self, msg, imphash=None):
        if not re.findall(r"(^[a-fA-F\d]{32})", imphash):
            return "Invalid imphash"

        api = self._api_factory()

        r = api.search_query("pefile.imphash={}".format(imphash))
        return PSSearchResultFormatter(r, color=False)

    def callback_message(self, message: Message) -> None:
        if message.is_direct:
            files_l = message.extras.get("slack_event", {}).get("files", [])
            if files_l:

                a = self._api_factory()
                for file in files_l:
                    # we're going to have rip this down the slack way in memory.
                    try:
                        download_response = requests.get(file['url_private'],
                                                         headers={"Authorization": "Bearer {}".format(self._bot.token)})
                        download_response.raise_for_status()

                        file_o = BytesIO(download_response.content)

                        hash = hashlib.sha256(file_o.read()).hexdigest()
                        self.send(message.frm,
                                  "Thanks for this upload. Sending off to PolySwarm (sha256: {})".format(hash))

                        polyswarm_resp = a.scan_fileobj(file_o, filename=file.get("name"))
                        poly_result = PolySwarmBaseResult(polyswarm_resp)
                        if not poly_result.status_ok:
                            self.send_templated(message.frm, "hash_search", {"hash": hash, "error": poly_result.reason})

                        br_obj = BountyResult(polyswarm_resp)
                        template_d = {
                            "latest_bounty_result": br_obj,
                            "assertions": br_obj.get_file_assertions(),
                            "defang_permalink": br_obj.permalink.replace("http", "hxxp"),
                            "hash": hash
                        }
                        self.send_templated(message.frm, "hash_search", template_d)

                    except Exception as e:
                        self.send(message.frm, "Sorry, error: {}".format(e))
                        self.log.error(e)

        elif message.is_group and message.extras.get("slack_event", {}).get("files", []):
            self.send(message.to,
                      "Hi there, please DM me potentially malicious files to scan. Don't post them in this public channel {}.".format(
                          message.frm))

        super().callback_message(message)

    @botcmd
    def poly_scan(self, *args, **kwargs):
        return "(Slack only) To scan a file in PolySwarm DM it to this bot."
