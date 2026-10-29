#!/usr/bin/env python3
"""Merge a base XCI/NSP and an update NSP with the pinned hactool BKTR reader.

Temporary common-ticket keys are private files, never arguments or log output.
The caller additionally verifies the resulting image against its known version hash.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from extract_exefs import (load_keys, container_entries, common_tickets, nca_inventory,
                           program_nca, record_offset, require)
from extract_romfs import index_romfs

# Lockpick_RCM writes these as 17 bytes: the 16-byte source plus a trailing NUL.
# hactool exits unless the value is exactly 16 bytes, before any BKTR check.
_LOCKPICK_KEK_SOURCE = re.compile(r'(?:mariko_)?master_kek_source_[0-9a-f]{2}\Z')


def copy_range(source, offset, size, target):
    with source.open('rb') as src, target.open('wb') as dst:
        src.seek(offset)
        while size:
            data = src.read(min(size, 8 << 20))
            require(bool(data), 'Truncated NCA')
            dst.write(data)
            size -= len(data)


def hactool_prod_keys(source, target):
    """Copy prod.keys for hactool. The caller's file is left unchanged.

    hactool knows no comments: it reads the rest of a line as the value, so a trailing `# note` makes it exit. The copy
    keeps only the `name = value` lines, read the way load_keys reads them (comments dropped, spaces trimmed).
    A Lockpick trailing NUL on master_kek_source / mariko_master_kek_source is dropped. Any other length is rejected
    without recording the key bytes.
    """
    lines = []
    for number, line in enumerate(Path(source).read_text().splitlines(), 1):
        body = line.split('#', 1)[0]
        if '=' not in body:
            continue
        name, value = (part.strip() for part in body.split('=', 1))
        if _LOCKPICK_KEK_SOURCE.fullmatch(name.lower()) is not None:
            require(re.fullmatch(r'[0-9a-fA-F]+', value) is not None, f'Invalid key encoding at line {number}')
            if len(value) == 34 and value[-2:].lower() == '00':
                value = value[:32]
            require(len(value) == 32, f'{name.lower()} must be 16 bytes')
        lines.append(f'{name} = {value}')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))


def merge(base, update, keys_path, hactool, output, *, base_romfs=None, allow_unverified=False):
    require(not output.exists(), 'Output exists')
    keys = load_keys(keys_path)
    inputs = []
    tickets = {}
    sources = ((update, True),) if base_romfs else ((base, False), (update, True))
    for source, is_update in sources:
        with source.open('rb') as f:
            kind, entries = container_entries(f, source.stat().st_size)
            require(not is_update or kind == 'nsp', 'Update must be an NSP')
            found = common_tickets(f, entries)
            for rights, key in found.items():
                require(rights not in tickets or tickets[rights] == key, 'Conflicting common tickets')
                tickets[rights] = key
            record, header = program_nca(nca_inventory(f, entries, keys), update=is_update)
            rights = header[0x230:0x240]
            require(rights == bytes(16) or rights in tickets, 'Missing common ticket')
            inputs.append((source, record, header))
    sections = [i for i in range(4) if inputs[-1][2][0x400+i*512+4] == 4]
    require(len(sections) == 1, 'Expected one BKTR section')
    output.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(output.parent).free > inputs[-1][1]['size'] + 18*(1 << 30),
            'Need about 19 GiB free for the temporary update NCA and merged image')
    if base_romfs:
        require(Path(base_romfs).is_file(), 'Previous-version RomFS is missing')
    with tempfile.TemporaryDirectory(prefix='update-merge-', dir=output.parent) as tmp:
        tmp = Path(tmp)
        keyfile = tmp/'title.keys'
        fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            for rights, key in tickets.items():
                f.write(f'{rights.hex()} = {key.hex()}\n')
        source, record, _ = inputs[-1]
        copy_range(source, record_offset(record), record['size'], tmp/'update.nca')
        result = tmp/'result'
        result.mkdir()
        base_arg = '--baseromfs='+str(Path(base_romfs).resolve()) if base_romfs else '--basenca='+str(base.resolve())
        environment = dict(os.environ, MNG_TITLE_KEYS=str(keyfile))
        environment.pop('MNG_BASE_RANGE_OFFSET', None); environment.pop('MNG_BASE_RANGE_SIZE', None)
        if not base_romfs:
            environment.update(MNG_BASE_RANGE_OFFSET=str(record_offset(inputs[0][1])),
                               MNG_BASE_RANGE_SIZE=str(inputs[0][1]['size']))
        hactool_keys = tmp/'hactool.keys'
        hactool_prod_keys(keys_path, hactool_keys)
        command = [str(hactool.resolve()), '-x', '-y', '--disablekeywarns', '--suppresskeys',
                   '-k', str(hactool_keys.resolve()), base_arg,
                   f'--section{sections[0]}='+str(result/'romfs.bin'), str(tmp/'update.nca')]
        with (result/'merge.log').open('w') as log:
            code = subprocess.run(command, env=environment,
                                  stdout=log, stderr=subprocess.STDOUT).returncode
        log = (result/'merge.log').read_text()
        # hactool also verifies the NCA's fixed-key and NPDM signatures, which need Nintendo's public keys:
        # without them it always prints those two lines as (FAIL). They are not data failures; the six IVFC
        # levels and the image SHA-256 recorded below decide whether the merge worked.
        unsigned = re.compile(r'\s*(?:Fixed-Key Signature|NPDM Signature) \(FAIL\)')
        checked = '\n'.join(line for line in log.splitlines() if not unsigned.match(line))
        failures = [line.strip() for line in checked.splitlines()
                    if re.search(r'\(FAIL\)|\(INVALID\)|Failed to|Error:', line)]
        missing = [i for i in range(6) if not re.search(rf'Level {i} \(GOOD\)', log)]
        overridden = False
        if code or failures or missing:
            # hactool repeats a key it cannot parse ("Key (<value>) must be 32 hex digits!"):
            # redact both the retained log and the error shown by build_app.py.
            def redact(text):
                return re.sub(r'[0-9A-Fa-f]{32,}', '<hex removed>', text)

            failure_log = output.parent/(output.name+'-failure.log')
            failure_log.write_text(redact(log))
            details = [f'hactool exit {code}'] if code else []
            details.extend(redact(line)[:240] for line in failures[:3])
            if missing and not failures:
                details.append('Missing verified IVFC levels: ' + ', '.join(map(str, missing)))
            # A content-ID mismatch alone can also mean a repacked NCA. Use it as a
            # diagnostic only after verification fails, never as a new import restriction.
            if re.fullmatch(r'[0-9a-fA-F]{32}\.nca', record['name']):
                with (tmp/'update.nca').open('rb') as f:
                    digest = hashlib.file_digest(f, 'sha256').hexdigest()
                if digest[:32] != record['name'][:32].lower():
                    details.append('Update Program NCA SHA-256 does not match its content ID; '
                                   'the update may be modified or damaged. Re-dump the update from your console')
            message = 'BKTR verification failed: ' + '; '.join(details) + f'; full details: {failure_log}'
            # The explicit override covers data checks only. Tool errors, incomplete
            # verification and unreadable/invalid structures must still stop extraction.
            overridden = (allow_unverified and code == 0 and bool(failures)
                          and all(re.fullmatch(r'Level [0-5] \(FAIL\):?', line) for line in failures)
                          and all(re.search(rf'Level {i} \((?:GOOD|FAIL)\)', log) for i in range(6)))
            require(overridden, message)
            print('WARNING: continuing with unverified update data: ' + message, flush=True)
        image = result/'romfs.bin'
        with image.open('rb') as f:
            digest = hashlib.file_digest(f, 'sha256').hexdigest()
        files = index_romfs(image)
        report = dict(status='unverified' if overridden else 'pass', romfs_size=image.stat().st_size,
                      romfs_sha256=digest, files=files,
                      integrity='UNVERIFIED: update data checks explicitly overridden' if overridden else
                                'BKTR merge; all six IVFC levels verified')
        if overridden:
            report['verification_failures'] = failures
        (result/'index.json').write_text(json.dumps(report, indent=2)+'\n')
        result.rename(output)
    print(json.dumps(dict(status=report['status'], files=len(files), sha256=digest)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path)
    parser.add_argument('update', type=Path)
    parser.add_argument('--keys', required=True, type=Path)
    parser.add_argument('--hactool', required=True, type=Path)
    parser.add_argument('--base-romfs', type=Path, help='full decrypted base IVFC section, including hash levels (not a raw RomFS image)')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--allow-unverified-update', action='store_true', help='continue after failed IVFC data checks and mark the output unverified')
    args = parser.parse_args()
    merge(args.base, args.update, args.keys, args.hactool, args.output, base_romfs=args.base_romfs,
          allow_unverified=args.allow_unverified_update)
