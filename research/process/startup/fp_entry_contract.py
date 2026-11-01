"""Validate captured FP fields without substituting an expected initial state."""


def validate_entry_fp(row):
    fields = ['fp_control', 'fp_status', 'fp_tag', 'fp_mxcsr', 'fp_mxcsr_mask']
    if type(row.get('fp_context_flags')) is not int or row['fp_context_flags'] & 0x10028 != 0x10028:
        raise ValueError('FP context categories not acquired')
    for name in fields:
        maximum = 0xffff if name in fields[:3] else 0xffffffff
        if type(row.get(name)) is not int or not 0 <= row[name] <= maximum:
            raise ValueError('FP capture field missing or invalid: '+name)
    return {name: row[name] for name in fields}
