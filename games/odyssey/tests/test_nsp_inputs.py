"""Synthetic NSP checks; needs cryptography, but no game data or keys.

Run: python -m unittest discover -s games/odyssey/tests -p test_nsp_inputs.py
"""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_odyssey
import extract_app_icon

spec = importlib.util.spec_from_file_location('odyssey_merge_romfs',
        Path(__file__).resolve().parents[1] / 'scripts/merge_romfs.py')
merge_romfs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge_romfs)


def encrypt(key, mode, data):
    ctx = Cipher(algorithms.AES(key), mode).encryptor()
    return ctx.update(data) + ctx.finalize()


def romfs(files):
    entries, payload = bytearray(), bytearray()
    for i, (name, data) in enumerate(files.items()):
        name = name.encode()
        next_offset = len(entries) + 32 + ((len(name) + 3) & ~3)
        entries += struct.pack('<IIQQII', 0, next_offset if i + 1 < len(files) else 0xffffffff,
                               len(payload), len(data), 0xffffffff, len(name))
        entries += name + bytes((-len(name)) % 4)
        payload += data
    directory = struct.pack('<6I', 0, 0xffffffff, 0xffffffff, 0, 0xffffffff, 0)
    return (struct.pack('<10Q', 80, 80, 0, 80, len(directory), 104, 0, 104, len(entries),
                        104 + len(entries)) + directory + entries + payload)


def ivfc(image):
    levels = [image]
    for _ in range(5):
        levels.insert(0, b''.join(hashlib.sha256(levels[0][i:i + 4096].ljust(4096, b'\0')).digest()
                                  for i in range(0, len(levels[0]), 4096)))
    fs = bytearray(512)
    fs[2:5] = bytes((0, 3, 3))
    fs[8:24] = struct.pack('<4sIII', b'IVFC', 0x20000, 32, 7)
    for i, data in enumerate(levels):
        struct.pack_into('<QQII', fs, 24 + i * 24, i * 4096, len(data), 12, 0)
    fs[0xc8:0xe8] = hashlib.sha256(levels[0] + bytes(4096 - len(levels[0]))).digest()
    return fs, b''.join(data + bytes((-len(data)) % 4096) for data in levels)


def tree(rows, total, fmt):
    # The actual BKTR parser reads one L1 node and one entry node.
    first = struct.pack('<iiqq', 0, 1, total, 0).ljust(0x4000, b'\0')
    second = struct.pack('<iiq', 0, len(rows), total)
    second += b''.join(struct.pack(fmt, *row) for row in rows)
    return first + second.ljust(0x4000, b'\0')


class NspInputs(unittest.TestCase):
    header_key = bytes(range(32))
    titlekek = bytes(range(16))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.keys = self.root / 'prod.keys'
        self.keys.write_text(f'header_key = {self.header_key.hex()}\ntitlekek_00 = {self.titlekek.hex()}\n')

    def nca(self, fs, section, identity, content_type=0, title=0x0100000000010000):
        key, rights = bytes([identity]) * 16, bytes([identity + 16]) * 16
        struct.pack_into('<II', fs, 0x140, 0, 1)
        header = bytearray(0xc00)
        header[0x200:0x204] = b'NCA3'
        header[0x205:0x207] = bytes((content_type, 1))
        struct.pack_into('<QQ', header, 0x208, len(header) + len(section), title)
        struct.pack_into('<II', header, 0x240, 6, (len(header) + len(section)) // 512)
        header[0x280:0x2a0] = hashlib.sha256(fs).digest()
        header[0x230:0x240] = rights
        header[0x400:0x600] = fs
        encrypted = b''.join(encrypt(self.header_key, modes.XTS(i.to_bytes(16, 'big')),
                                     header[i * 512:(i + 1) * 512]) for i in range(6))
        body = encrypt(key, modes.CTR(fs[0x140:0x148][::-1] + (0xc00 // 16).to_bytes(8, 'big')), section)
        ticket = bytearray(0x140 + 0x180)
        struct.pack_into('<I', ticket, 0, 0x10004)
        ticket[0x180:0x190] = encrypt(self.titlekek, modes.ECB(), key)
        ticket[0x2a0:0x2b0] = rights
        return {f'{identity}.nca': encrypted + body, f'{identity}.tik': ticket}

    def nsp(self, name, entries):
        strings, table, payload = bytearray(), bytearray(), bytearray()
        for filename, data in entries.items():
            table += struct.pack('<QQII', len(payload), len(data), len(strings), 0)
            strings += filename.encode() + b'\0'
            payload += data
        path = self.root / name
        path.write_bytes(struct.pack('<4sIII', b'PFS0', len(entries), len(strings), 0) + table + strings + payload)
        return path

    def packages(self, title=0x0100000000010000):
        image = romfs({'hello.txt': b'updated content'})
        fs, section = ivfc(image)
        base = self.nca(bytearray(fs), section[:-4096] + bytes(4096), 1)
        update_fs = bytearray(fs)
        update_fs[4] = 4
        ind = tree([(0, 0, 0), (5 * 4096, 0, 1)], 5 * 4096 + len(image), '<qqi')
        ind_offset = 4096
        ex_offset = ind_offset + len(ind)
        ex = tree([(0, 0, 0)], ex_offset, '<qB3xi')
        struct.pack_into('<QQ4sIi', update_fs, 0x100, ind_offset, len(ind), b'BKTR', 1, 2)
        struct.pack_into('<QQ4sIi', update_fs, 0x120, ex_offset, len(ex), b'BKTR', 1, 1)
        update = self.nca(update_fs, image.ljust(4096, b'\0') + ind + ex, 2, title=title)
        return base, update, image

    def merge(self, game, update, output):
        argv = ['merge_romfs.py', str(game), '--keys', str(self.keys), '--output', str(output)]
        if update:
            argv += ['--update', str(update)]
        with patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()):
            merge_romfs.main()

    def test_separate_and_combined_packages_match(self):
        base, update, image = self.packages()
        base_path = self.nsp('base.nsp', base)
        update_path = self.nsp('update.nsp', update)
        combined_path = self.nsp('combined.nsp', {**base, **update})
        for label, game, update in [('separate', base_path, update_path), ('combined', combined_path, None)]:
            with self.subTest(label=label):
                output = self.root / label
                self.merge(game, update, output)
                self.assertEqual((output / 'romfs.bin').read_bytes(), image)
                report = json.loads((output / 'index.json').read_text())
                self.assertEqual(report['ivfc_blocks'], [1] * 6)
                self.assertGreater(report['bytes_from_base'], 0)
                self.assertGreater(report['bytes_from_update'], 0)
                self.assertEqual(report['files'][0]['path'], 'hello.txt')

    def test_rejects_reversed_missing_and_foreign_update(self):
        base, update, _ = self.packages()
        base_path, update_path = self.nsp('base.nsp', base), self.nsp('update.nsp', update)
        _, foreign, _ = self.packages(title=0x0100000000000000)
        for game, update in [(update_path, base_path), (base_path, None),
                             (base_path, self.nsp('foreign.nsp', foreign))]:
            with self.subTest(game=game, update=update), self.assertRaises(ValueError):
                self.merge(game, update, self.root / 'rejected')
                self.fail('invalid input accepted')

    def test_update_only_icon_and_custom_work_folder(self):
        jpeg = b'\xff\xd8\xffsynthetic icon\xff\xd9'
        for version in ('1.3.0', '1.4.1'):
            with self.subTest(version=version):
                nacp = bytearray(0x3070)
                nacp[0x3060:0x3065] = version.encode()
                fs, section = ivfc(romfs({'control.nacp': nacp, 'icon_AmericanEnglish.dat': jpeg}))
                update = self.nsp('control.nsp', self.nca(fs, section, 3, content_type=2))
                output = self.root / 'custom_build/app-assets/icon.jpg'
                with patch.object(extract_app_icon, 'HERE', self.root), patch.object(sys, 'argv',
                        ['extract_app_icon.py', str(update), '--keys', str(self.keys), '--output', str(output)]), \
                        redirect_stdout(io.StringIO()):
                    extract_app_icon.main()
                self.assertEqual(output.read_bytes(), jpeg)
                self.assertEqual(output.with_name('game-version.txt').read_text(), version + '\n')

    def test_builder_routes_both_input_modes(self):
        for separate in (False, True):
            with self.subTest(separate=separate):
                work = self.root / ('separate_build' if separate else 'combined_build')
                game, update = self.root / 'base.nsp', self.root / 'update.nsp'
                argv = ['build_odyssey.py', '--game', str(game), '--keys', str(self.keys),
                        '--firmware', str(self.root), '--work', str(work), '--skip-seed']
                if separate:
                    argv += ['--update', str(update)]
                with patch.object(sys, 'argv', argv), patch.object(build_odyssey, 'preflight'), \
                        patch.object(build_odyssey, 'run') as run, redirect_stdout(io.StringIO()):
                    build_odyssey.main()
                commands = [call.args[0] for call in run.call_args_list]
                def command(script):
                    return next(cmd for cmd in commands if len(cmd) > 1 and cmd[1] == f'scripts/{script}.py')
                expected = update if separate else game
                self.assertEqual(command('extract_code')[2], expected)
                self.assertEqual(command('extract_app_icon')[2], expected)
                self.assertEqual('--update' in command('merge_romfs'), separate)
                if separate:
                    merge = command('merge_romfs')
                    self.assertEqual(merge[merge.index('--update') + 1], update)
                    self.assertIn(update, [cmd[2] for cmd in commands if cmd[1] == 'scripts/inspect_input.py'])


if __name__ == '__main__':
    unittest.main()
