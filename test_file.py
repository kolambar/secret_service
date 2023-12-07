from services import code_it, decode_it


def test_code_and_decode():
    ciphertext = code_it('user_key', 'user_secret')

    assert 'user_secret' == decode_it('user_key', ciphertext)
