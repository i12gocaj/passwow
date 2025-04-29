from vault.recovery import split_secret, recover_secret

def test_split_and_recover_basic():
    secret = "mySecret123!"
    n, k = 5, 3
    shares = split_secret(secret, n, k)
    # Should produce n shares
    assert isinstance(shares, list)
    assert len(shares) == n
    # Recover using first k shares
    recovered = recover_secret(shares[:k])
    assert recovered == secret

def test_recover_insufficient_shares_wrong():
    secret = "anotherSecret"
    n, k = 4, 3
    shares = split_secret(secret, n, k)
    recovered = recover_secret(shares[:k-1])
    assert recovered != secret

def test_shares_are_unique_and_valid():
    secret = "uniqueTest"
    n, k = 6, 2
    shares = split_secret(secret, n, k)
    # All shares should be distinct
    assert len(set(shares)) == n
    # Each share should match the expected format "hex-..." 
    for share in shares:
        parts = share.split("-")
        # Format: identifier-hexstring
        assert len(parts) == 2
        identifier, hexdata = parts
        # Identifier should be integer-like
        assert identifier.isdigit()
        # Hexdata should be valid hex
        int(hexdata, 16)