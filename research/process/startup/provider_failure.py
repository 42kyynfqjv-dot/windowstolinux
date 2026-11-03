"""Independent loader failure expectations, not native admission authority."""
def validate(row):
    for key in ('before_absent','after_first_absent','after_second_absent','held_after_one_release','absent_after_final_release'):
        if row.get(key) is not True:raise ValueError('module lifetime observation: '+key)
    for key,expected in [('first_error',1114),('second_error',1114),('value',7)]:
        if type(row.get(key)) is not int or row[key]!=expected:raise ValueError('loader result: '+key)
    return row
