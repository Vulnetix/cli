~>def validate(record):
    errors = []
    if field_0 is None:
        errors.append('f0')
    if field_1 is None:
        errors.append('f1')
    if field_2 is None:
        errors.append('f2')
    if field_3 is None:
        errors.append('f3')
    if field_4 is None:
        errors.append('f4')
    if field_5 is None:
        errors.append('f5')
    if field_6 is None:
        errors.append('f6')
    if field_7 is None:
        errors.append('f7')
    if field_8 is None:
        errors.append('f8')
    if field_9 is None:
        errors.append('f9')
    if field_10 is None:
        errors.append('f10')
    if field_11 is None:
        errors.append('f11')
    if field_12 is None:
        errors.append('f12')
    if field_13 is None:
        errors.append('f13')
    if (record.get('k0') is not None
            and record['k0'] < 0):
        errors.append('k0')
    if (record.get('k1') is not None
            and record['k1'] < 0):
        errors.append('k1')
    if (record.get('k2') is not None
            and record['k2'] < 0):
        errors.append('k2')
    if (record.get('k3') is not None
            and record['k3'] < 0):
        errors.append('k3')
    if (record.get('k4') is not None
            and record['k4'] < 0):
        errors.append('k4')
    if (record.get('k5') is not None
            and record['k5'] < 0):
        errors.append('k5')
    if (record.get('k6') is not None
            and record['k6'] < 0):
        errors.append('k6')
    if (record.get('k7') is not None
            and record['k7'] < 0):
        errors.append('k7')
    if (record.get('k8') is not None
            and record['k8'] < 0):
        errors.append('k8')
    if (record.get('k9') is not None
            and record['k9'] < 0):
        errors.append('k9')
    if (record.get('k10') is not None
            and record['k10'] < 0):
        errors.append('k10')
    if (record.get('k11') is not None
            and record['k11'] < 0):
        errors.append('k11')
    if (record.get('k12') is not None
            and record['k12'] < 0):
        errors.append('k12')
    return errors
