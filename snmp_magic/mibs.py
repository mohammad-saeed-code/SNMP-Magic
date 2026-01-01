# snmp_magic/mibs.py
OID = {
    # System
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",

    # IF-MIB base
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifMtu": "1.3.6.1.2.1.2.2.1.4",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",           # in bps (32-bit)
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",   # in Mbps (preferred)
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifLastChange": "1.3.6.1.2.1.2.2.1.9",

    # IF-MIB octets (use 64-bit HC if available)
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",

    # BRIDGE-MIB
    "dot1dBasePortIfIndex": "1.3.6.1.2.1.17.1.4.1.2",
    "dot1dTpFdbAddress": "1.3.6.1.2.1.17.4.3.1.1",
    "dot1dTpFdbPort":    "1.3.6.1.2.1.17.4.3.1.2",
    "dot1dTpFdbStatus":  "1.3.6.1.2.1.17.4.3.1.3",

    # Q-BRIDGE-MIB (VLANs)
    "dot1qVlanStaticName": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "dot1qVlanStaticEgressPorts": "1.3.6.1.2.1.17.7.1.4.3.1.2",
    "dot1qVlanStaticUntaggedPorts": "1.3.6.1.2.1.17.7.1.4.3.1.4",
    "dot1qVlanCurrentEgressPorts": "1.3.6.1.2.1.17.7.1.4.2.1.4",
    "dot1qPvid": "1.3.6.1.2.1.17.7.1.4.5.1.1",
    "dot1qTpFdbPort":    "1.3.6.1.2.1.17.7.1.2.2.1.2",
    "dot1qTpFdbStatus":  "1.3.6.1.2.1.17.7.1.2.2.1.3",

    # LLDP-MIB
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpRemPortIdSubtype": "1.0.8802.1.1.2.1.4.1.1.6",      
    "lldpRemChassisIdSubtype": "1.0.8802.1.1.2.1.4.1.1.4",    

    # EtherLike-MIB (duplex)
    "dot3StatsDuplexStatus": "1.3.6.1.2.1.10.7.2.1.19",  # 1=unknown,2=half,3=full
}
