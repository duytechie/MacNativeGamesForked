#!/usr/bin/env python3
"""Verify and merge Odyssey base AES-CTR RomFS with its BKTR update.

Game data and keys remain local. The update IVFC authenticates every output block.
"""
import argparse
from contextlib import ExitStack
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / 'third_party/by3-scripts'))
from extract_exefs import (load_keys, container_entries, common_tickets,
                           nca_inventory, nca_ctr_key, require)
from extract_romfs import index_romfs

spec = importlib.util.spec_from_file_location('by3_merge_romfs', HERE / 'third_party/by3-scripts/merge_romfs.py')
by3_merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(by3_merge)
Ctr, Patched = by3_merge.Ctr, by3_merge.Patched
romfs_section, verify_ivfc = by3_merge.romfs_section, by3_merge.verify_ivfc


class DirectBase:
    def __init__(self, ctr, start, end, fs):
        require(fs[4] == 3, 'Expected a direct AES-CTR base RomFS')
        require(end <= ctr.size, 'Base RomFS exceeds stored NCA')
        self.ctr, self.start, self.size = ctr, start, end - start
        self.upper = fs[0x140:0x148][::-1]

    def read(self, offset, size):
        require(0 <= offset and offset + size <= self.size, 'Base RomFS read out of bounds')
        return self.ctr.read(self.start + offset, size, self.upper)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('game', type=Path, help='Local Odyssey base XCI/NSP, or combined base + update package')
    parser.add_argument('--update', type=Path, help='Separate Odyssey update 1.3.0 NSP')
    parser.add_argument('--keys', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), 'Output already exists')
    keys = load_keys(args.keys)
    with ExitStack() as stack:
        def inventory(path):
            source = stack.enter_context(path.open('rb'))
            _, entries = container_entries(source, path.stat().st_size)
            records = nca_inventory(source, entries, keys)
            programs = [(r, h, romfs_section(h)) for r, h in records
                        if r['content_type'] == 0 and r['title_id'] == '0100000000010000']
            return source, programs, common_tickets(source, entries)

        base_source, base_sections, base_tickets = inventory(args.game)
        if args.update:
            update_source, update_sections, update_tickets = inventory(args.update)
            require(len(base_sections) == len(update_sections) == 1,
                    'Expected one Odyssey Program NCA in each separate base and update package')
        else:
            require(len(base_sections) == 2, 'Expected exactly one base and one update Program NCA; '
                    'for separate packages pass --update UPDATE.nsp')
            update_source, update_sections, update_tickets = base_source, base_sections, base_tickets
        base_items = [(r, h, s) for r, h, s in base_sections if s[2][4] == 3]
        update_items = [(r, h, s) for r, h, s in update_sections if s[2][4] == 4]
        require(len(base_items) == len(update_items) == 1, 'Expected direct base and BKTR update RomFS')
        brec, bhdr, (bstart, bend, bfs) = base_items[0]
        urec, uhdr, (ustart, uend, ufs) = update_items[0]
        base_ctr = Ctr(base_source, brec['nca_offset'], brec['size'], nca_ctr_key(bhdr, keys, base_tickets))
        update_ctr = Ctr(update_source, urec['nca_offset'], urec['size'], nca_ctr_key(uhdr, keys, update_tickets))
        base = DirectBase(base_ctr, bstart, bend, bfs)
        patched = Patched(update_ctr, ustart, uend, ufs, base)
        args.output.mkdir(parents=True)
        image = args.output / 'romfs.bin'
        counts, size, digest = verify_ivfc(ufs, patched.total, patched.read, image)
        files = index_romfs(image)
        report = dict(status='pass', base_program=brec, update_program=urec,
                      source_size=args.game.stat().st_size + (args.update.stat().st_size if args.update else 0),
                      ivfc_blocks=counts,
                      romfs_size=size, romfs_sha256=digest,
                      bytes_from_base=patched.from_base, bytes_from_update=patched.from_update,
                      files=files,
                      integrity='FS headers and all six update IVFC levels verified; RSA signatures not checked')
        (args.output / 'index.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(status='pass', files=len(files), size=size, sha256=digest,
                              from_base=patched.from_base, from_update=patched.from_update)), flush=True)


if __name__ == '__main__':
    main()
