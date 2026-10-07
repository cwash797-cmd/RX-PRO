import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

from s3_profile import profile, write_private


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.client = {"endpoint": "https://hb.ru-msk.vkcloud-storage.ru", "region": "ru-msk",
            "bucket": "test-bucket", "prefix": "probe-tests/data/device1/", "accessKey": "CLIENT", "secretKey": "CLIENT-SECRET"}
        self.server = dict(self.client, prefix="probe-tests/data/", accessKey="SERVER", secretKey="SERVER-SECRET")
        self.link = "vless://00000000-0000-4000-8000-000000000001@127.0.0.1:10001?type=tcp&security=none&encryption=mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#Test"

    def test_identity_scope_and_server_secret_separation(self):
        link, bridge, pc = profile(self.link, self.client, self.server, 10001)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)
        s = q["s3"][0]
        data = json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        self.assertEqual(data["accessKey"], "CLIENT")
        self.assertNotIn("SERVER-SECRET", link + json.dumps(pc))
        self.assertIn(".1rtt.", q["encryption"][0])
        inbound = bridge["inbounds"][0]
        self.assertEqual(inbound["settings"]["address"], "127.0.0.1")
        self.assertEqual(inbound["settings"]["port"], 10001)
        self.assertEqual(inbound["streamSettings"]["xdriveSettings"]["remoteFolder"], "probe-tests/data/device1")
        self.assertEqual(len(pc["outbounds"]), 1)
        self.assertEqual(pc["outbounds"][0]["protocol"], "vless")

    def test_rejects_plaintext_and_wrong_transport(self):
        for value in [self.link.replace("type=tcp", "type=ws"), self.link.split("&encryption=")[0],
                      self.link.replace("security=none", "security=reality"), self.link.replace("#Test", "&flow=xtls-rprx-vision")]:
            with self.assertRaises(ValueError):
                profile(value, self.client, self.server, 10001)

    def test_rejects_sibling_prefix(self):
        bad = dict(self.server, prefix="probe-tests/data/device2")
        with self.assertRaises(ValueError):
            profile(self.link, self.client, bad, 10001)

    def test_credential_bearing_names_are_sanitized(self):
        for name in ["prefix-vless://fixture@localhost", "s3=fixture", "accessKey=fixture", "x" * 81]:
            link, _, _ = profile(self.link.split("#")[0] + "#" + urllib.parse.quote(name), self.client, self.server, 10001)
            self.assertEqual(urllib.parse.unquote(urllib.parse.urlsplit(link).fragment), "VK S3")

    def test_normal_name_is_preserved(self):
        link, _, _ = profile(self.link.split("#")[0] + "#" + urllib.parse.quote("Мой VK"), self.client, self.server, 10001)
        self.assertEqual(urllib.parse.unquote(urllib.parse.urlsplit(link).fragment), "Мой VK")

    def test_never_overwrites_existing_secret_file(self):
        root = Path(__file__).resolve().parents[1] / ".lab"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as folder:
            path = Path(folder) / "secret"
            write_private(path, "one")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_private(path, "two")
            self.assertEqual(path.read_text(), "one")


if __name__ == "__main__":
    unittest.main()
