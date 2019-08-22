import shutil
import tempfile
from io import BytesIO

import polyquery
from zipfile import ZipFile
import hashlib

from errbot.backends.base import Stream

pytest_plugins = ["errbot.backends.test"]
extra_plugin_dir = '.'
EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
EICAR_SHA1 = '3395856ce81f2b7382dee72602f798b642f14140'
EICAR_MD5 = '44d88612fea8a8f36de82e1278abb02f'
EICAR_CONTENT = b'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
ALL_HASHES = [EICAR_SHA256, EICAR_MD5, EICAR_SHA1]
DOES_NOT_EXIST_SHA256 = hashlib.sha256(b"hi, this content doesn't exist in polyswarm.").hexdigest()
DEFAULT_TIMEOUT = 30




def test_download(testbot):
    for h in ALL_HASHES:
        testbot.push_message("!poly download {}".format(h))
        file_bytes = testbot.pop_message(timeout=30, block=True)
        d = tempfile.mkdtemp()
        try:
            zf = ZipFile(BytesIO(file_bytes), 'r')
            zf.extractall(path=d, pwd=b"infected")
            # todo inspect content via hash
        finally:
            shutil.rmtree(d)

        m = testbot.pop_message(timeout=30, block=True)
        assert 'File ready' in m

def test_bad_download(testbot):
    testbot.push_message("!poly download {}".format(DOES_NOT_EXIST_SHA256))
    m = testbot.pop_message(timeout=30, block=True)
    assert 'file_not_found' in m

    testbot.push_message("!poly download deadbeef")
    m = testbot.pop_message(timeout=2, block=True)
    assert "Invalid hash" in m

def test_search(testbot):
    for h in ALL_HASHES:
        testbot.push_message("!poly search {}".format(h))
        response = testbot.pop_message(timeout=DEFAULT_TIMEOUT, block=True)
        assert "reporting malicious" in response

def test_bad_search(testbot):
    testbot.push_message("!poly search {}".format(DOES_NOT_EXIST_SHA256))
    response = testbot.pop_message(timeout=DEFAULT_TIMEOUT, block=True)
    assert "No entries found" in response

# todo have to find automated way to test upload scan.