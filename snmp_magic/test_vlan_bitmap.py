from snmp_magic.vlan import decode_bitmap

def test_decode_bitmap_empty():
    assert decode_bitmap(None) == set()

def test_decode_bitmap_simple():
    # 0x80 => 1000 0000 => port 1 set
    assert decode_bitmap(bytes([0x80])) == {1}
    # 0x40 => 0100 0000 => port 2 set
    assert decode_bitmap(bytes([0x40])) == {2}
    # 0xC0 => 1100 0000 => ports 1 and 2 set
    assert decode_bitmap(bytes([0xC0])) == {1,2}

def test_decode_bitmap_multi_octet():
    # [0x80, 0x01] => port1 and port16
    assert decode_bitmap(bytes([0x80, 0x01])) == {1,16}
