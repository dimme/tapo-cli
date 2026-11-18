import base64
import runpy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class DownloadVideosTest(unittest.TestCase):
    def setUp(self):
        module = runpy.run_path(str(Path(__file__).with_name('tapo-cli.py')))
        self.cli = module['tapo']
        self.globals = module['download_videos'].callback.__globals__

    def run_download(self, directory, clips, responses):
        devices = {'deviceList': [{'deviceId': 'fixture-device', 'alias': 'Camera'}]}
        videos = {'index': [
            {'eventLocalTime': f'2026-01-02 03:04:{second:02d}', 'video': [clip]}
            for second, clip in enumerate(clips)], 'total': len(clips)}
        with patch.dict(self.globals, {'get_config': lambda: None,
                                       'probe_endpoint_post': lambda *_: devices,
                                       'probe_endpoint_get': lambda *_: videos}), \
                patch.object(self.globals['requests'], 'get',
                             side_effect=lambda url: SimpleNamespace(content=responses[url])):
            return CliRunner().invoke(self.cli, ['download-videos', '--days', '1',
                                                '--path', str(directory), '--overwrite', '0'])

    def test_explicit_none_does_not_block_next_aes_clip(self):
        plain_url = 'https://media.example/plain'
        aes_url = 'https://media.example/aes'
        legacy_url = 'https://media.example/legacy'
        key, iv = b'K' * 16, b'I' * 16
        aes = AES.new(key, AES.MODE_CBC, iv)
        clips = [
            {'uri': plain_url, 'encryptionMethod': 'NONE'},
            {'uri': aes_url, 'encryptionMethod': 'AES-128-CBC',
             'decryptionInfo': {'key': base64.b64encode(key).decode()}},
            {'uri': legacy_url},
        ]
        responses = {
            plain_url: b'plain clip',
            aes_url: iv + aes.encrypt(pad(b'decrypted clip', AES.block_size)),
            legacy_url: b'legacy clip',
        }
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_download(directory, clips, responses)
            self.assertEqual(result.exit_code, 0, result.output)
            saved = sorted((Path(directory) / 'Camera' / '2026-01-02').glob('*.mp4'))
            self.assertEqual([path.read_bytes() for path in saved],
                             [b'plain clip', b'decrypted clip', b'legacy clip'])

    def test_unknown_method_is_not_written_as_a_video(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_download(directory, [
                {'uri': 'https://media.example/unknown', 'encryptionMethod': 'FUTURE'}], {})
            self.assertEqual(result.exit_code, 1)
            self.assertIn('Unsupported encryption method: FUTURE', result.output)
            self.assertEqual(list(Path(directory).rglob('*.mp4')), [])


if __name__ == '__main__':
    unittest.main()
