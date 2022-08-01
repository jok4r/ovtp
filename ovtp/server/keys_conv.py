import re


def get_short_rsa_key(key):
    r = re.search(rb'-----BEGIN RSA PUBLIC KEY-----(.*)-----END RSA PUBLIC KEY-----', key)
    if r:
        return r.group(1)
    else:
        raise ValueError(f'Bad rsa key: {key}')


def short_key_to_full(key):
    return b'%b\n%b\n%b' % (
        b'-----BEGIN RSA PUBLIC KEY-----',
        key,
        b'-----END RSA PUBLIC KEY-----'
    )
