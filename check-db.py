from snmp_magic.store import engine, Device
from sqlmodel import Session, select

with Session(engine) as s:
    devs = s.exec(select(Device)).all()
    for d in devs:
        print(f"{d.ip} | type={d.device_type} | name={d.sys_name} | descr={d.sys_descr}")