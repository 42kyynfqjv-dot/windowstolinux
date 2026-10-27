"""Strict evidence inventory, separate from executable/hash verification."""
def validate_report(report, manifest, cases):
    assert report['manifest'] == manifest, 'heap evidence: manifest'
    assert [r['name'] for r in report['programs']] == manifest['programs'], 'heap evidence: program inventory'
    names = [c['name'] for c in cases]
    assert len(set(names)) == len(names) == 16, 'heap evidence: frozen case inventory'
    for row in report['programs']:
        assert [o['name'] for o in row['observations']] == names, 'heap evidence: observation inventory'
        for case, observation in zip(cases, row['observations']):
            assert observation['executed_sha256'] == row['pe_sha256'], 'heap evidence: executed image'
            assert observation['timeout'] is False, 'heap evidence: timed out observation'
            assert (observation['exit'], observation['stdout_hex'], observation['stderr_hex']) == (
                0, case['expected'][row['name']], ''), 'heap evidence: original outcome'
        for key, code in [('read_failure', 11), ('write_failure', 14)]:
            failure = row[key]
            assert failure['executed_sha256'] == row['pe_sha256'], 'heap evidence: error image'
            assert failure['timeout'] is False, 'heap evidence: timed out error case'
            assert (failure['exit'], failure['stdout_hex'], failure['stderr_hex']) == (code, '', ''), 'heap evidence: error outcome'
        assert row['conversion']['exit'] == 1, 'heap evidence: required conversion barrier'
