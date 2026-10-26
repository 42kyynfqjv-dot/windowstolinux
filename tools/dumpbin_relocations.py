"""Read the bounded observed English dumpbin relocation listing, test-only."""
import re


def highlow_words(text):
    page = None
    result = []
    for line in text.splitlines():
        block = re.fullmatch(r'\s*([0-9A-Fa-f]+) RVA,\s*[0-9A-Fa-f]+ SizeOfBlock\s*', line)
        if block:
            page = int(block[1], 16)
        record = re.fullmatch(r'\s*([0-9A-Fa-f]+)\s+HIGHLOW\s+([0-9A-Fa-f]+)\s*', line)
        if record:
            if page is None:
                raise ValueError('HIGHLOW without page')
            result.append((page + int(record[1], 16), int(record[2], 16)))
    if not result:
        raise ValueError('no recognized HIGHLOW records; check tool output format')
    return result
