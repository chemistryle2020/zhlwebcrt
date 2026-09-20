"""凭据管理 API（密码 Fernet 加密存储，永不明文返回）。"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Credential, Device
from ..schemas import CredentialIn, CredentialOut
from ..core.collector import encrypt

router = APIRouter(prefix="/api/credentials", tags=["credentials"])


@router.get("", response_model=list[CredentialOut])
def list_credentials(db: Session = Depends(get_db)):
    return db.query(Credential).order_by(Credential.id).all()


@router.post("", response_model=CredentialOut)
def create_credential(body: CredentialIn, db: Session = Depends(get_db)):
    if db.query(Credential).filter(Credential.name == body.name).first():
        raise HTTPException(400, f"凭据名称 '{body.name}' 已存在")
    cred = Credential(
        name=body.name,
        username=body.username,
        password_enc=encrypt(body.password),
        enable_password_enc=encrypt(body.enable_password),
        description=body.description,
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


@router.put("/{cred_id}", response_model=CredentialOut)
def update_credential(cred_id: int, body: CredentialIn, db: Session = Depends(get_db)):
    cred = db.get(Credential, cred_id)
    if not cred:
        raise HTTPException(404, "凭据不存在")
    cred.name = body.name
    cred.username = body.username
    if body.password:  # 留空表示不修改密码
        cred.password_enc = encrypt(body.password)
    if body.enable_password:
        cred.enable_password_enc = encrypt(body.enable_password)
    cred.description = body.description
    db.commit()
    db.refresh(cred)
    return cred


@router.delete("/{cred_id}")
def delete_credential(cred_id: int, db: Session = Depends(get_db)):
    cred = db.get(Credential, cred_id)
    if not cred:
        raise HTTPException(404, "凭据不存在")
    used = db.query(Device).filter(Device.credential_id == cred_id).count()
    if used:
        raise HTTPException(400, f"该凭据正被 {used} 台设备使用，无法删除")
    db.delete(cred)
    db.commit()
    return {"ok": True}
