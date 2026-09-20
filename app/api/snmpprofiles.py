"""SNMP 模板管理 API（community/密钥加密存储，永不明文返回）。"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..core.collector import encrypt
from ..database import get_db
from ..models import Device, SnmpProfile
from ..schemas import SnmpProfileIn, SnmpProfileOut

router = APIRouter(prefix="/api/snmp-profiles", tags=["snmp-profiles"])


@router.get("", response_model=list[SnmpProfileOut])
def list_profiles(db: Session = Depends(get_db)):
    return db.query(SnmpProfile).order_by(SnmpProfile.id).all()


@router.post("", response_model=SnmpProfileOut)
def create_profile(body: SnmpProfileIn, db: Session = Depends(get_db)):
    if db.query(SnmpProfile).filter(SnmpProfile.name == body.name).first():
        raise HTTPException(400, f"模板名称 '{body.name}' 已存在")
    if body.version not in ("v2c", "v3"):
        raise HTTPException(400, "version 必须是 v2c 或 v3")
    prof = SnmpProfile(
        name=body.name,
        version=body.version,
        port=body.port,
        community_enc=encrypt(body.community),
        v3_user=body.v3_user,
        v3_auth_key_enc=encrypt(body.v3_auth_key),
        v3_priv_key_enc=encrypt(body.v3_priv_key),
        v3_auth_proto=body.v3_auth_proto,
        v3_priv_proto=body.v3_priv_proto,
        description=body.description,
    )
    db.add(prof)
    db.commit()
    db.refresh(prof)
    return prof


@router.put("/{profile_id}", response_model=SnmpProfileOut)
def update_profile(profile_id: int, body: SnmpProfileIn, db: Session = Depends(get_db)):
    prof = db.get(SnmpProfile, profile_id)
    if not prof:
        raise HTTPException(404, "模板不存在")
    prof.name = body.name
    prof.version = body.version
    prof.port = body.port
    if body.community:  # 留空表示不修改
        prof.community_enc = encrypt(body.community)
    prof.v3_user = body.v3_user
    if body.v3_auth_key:
        prof.v3_auth_key_enc = encrypt(body.v3_auth_key)
    if body.v3_priv_key:
        prof.v3_priv_key_enc = encrypt(body.v3_priv_key)
    prof.v3_auth_proto = body.v3_auth_proto
    prof.v3_priv_proto = body.v3_priv_proto
    prof.description = body.description
    db.commit()
    db.refresh(prof)
    return prof


@router.delete("/{profile_id}")
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    prof = db.get(SnmpProfile, profile_id)
    if not prof:
        raise HTTPException(404, "模板不存在")
    used = db.query(Device).filter(Device.snmp_profile_id == profile_id).count()
    if used:
        raise HTTPException(400, f"该模板正被 {used} 台设备使用，无法删除")
    db.delete(prof)
    db.commit()
    return {"ok": True}


@router.post("/{profile_id}/test")
def test_profile(profile_id: int, host: str, db: Session = Depends(get_db)):
    """对指定 IP 测试 SNMP 连通性（返回 sysDescr 前几十字）。"""
    from ..core import snmp
    from ..core.collector import decrypt

    prof = db.get(SnmpProfile, profile_id)
    if not prof:
        raise HTTPException(404, "模板不存在")
    profile = {
        "version": prof.version,
        "port": prof.port,
        "community": decrypt(prof.community_enc),
        "v3_user": prof.v3_user,
        "v3_auth_key": decrypt(prof.v3_auth_key_enc),
        "v3_priv_key": decrypt(prof.v3_priv_key_enc),
        "v3_auth_proto": prof.v3_auth_proto,
        "v3_priv_proto": prof.v3_priv_proto,
    }
    online, latency = snmp.probe(profile, host)
    if not online:
        return {"ok": False, "message": "SNMP 无响应（检查 community/版本/网络可达性）"}
    asset = snmp.get_asset(profile, host)
    return {
        "ok": True,
        "latency_ms": latency,
        "sys_name": (asset or {}).get("sys_name", ""),
        "sys_descr": (asset or {}).get("sys_descr", "")[:120],
        "version": (asset or {}).get("version", ""),
    }
