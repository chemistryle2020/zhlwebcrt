"""Pydantic 请求/响应模型。"""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------- 凭据 ----------
class CredentialIn(BaseModel):
    name: str
    username: str
    password: str
    enable_password: str = ""
    description: str = ""


class CredentialOut(BaseModel):
    id: int
    name: str
    username: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- 设备 ----------
class DeviceIn(BaseModel):
    name: str
    host: str
    port: int = 22
    protocol: str = "ssh"
    device_type: str = "huawei"
    group_name: str = "默认"
    credential_id: Optional[int] = None
    snmp_profile_id: Optional[int] = None
    description: str = ""
    enabled: bool = True


# ---------- SNMP 模板 ----------
class SnmpProfileIn(BaseModel):
    name: str
    version: str = "v2c"          # v2c / v3
    port: int = 161
    community: str = ""
    v3_user: str = ""
    v3_auth_key: str = ""
    v3_priv_key: str = ""
    v3_auth_proto: str = "MD5"    # MD5 / SHA
    v3_priv_proto: str = "DES"    # DES / AES
    description: str = ""


class SnmpProfileOut(BaseModel):
    id: int
    name: str
    version: str
    port: int
    v3_user: str
    v3_auth_proto: str
    v3_priv_proto: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


class DeviceOut(DeviceIn):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- 任务 ----------
class TaskIn(BaseModel):
    name: str
    commands: list[str] = Field(min_length=1)
    device_ids: list[int] = Field(min_length=1)


class TaskOut(BaseModel):
    id: int
    name: str
    status: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    total: int
    success: int
    failed: int
    trigger: str

    class Config:
        from_attributes = True


class TaskResultOut(BaseModel):
    id: int
    task_id: int
    device_name: str
    status: str
    error: str
    has_change: bool
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


# ---------- 模式/设置 ----------
class ModeIn(BaseModel):
    mode: str  # collect / config


class SettingsIn(BaseModel):
    cmd_whitelist: Optional[list[str]] = None
    diff_ignore_patterns: Optional[list[str]] = None
    concurrency: Optional[int] = None
    connect_timeout: Optional[int] = None
    read_timeout: Optional[int] = None
    retry: Optional[int] = None
    monitor_enabled: Optional[bool] = None
    monitor_interval_min: Optional[int] = None
    cpu_threshold: Optional[int] = None
    mem_threshold: Optional[int] = None


# ---------- 定时任务 ----------
class ScheduleIn(BaseModel):
    name: str
    cron: str = Field(description="5 段 cron，如 0 3 * * *")
    commands: list[str] = Field(min_length=1)
    device_group: str = ""
    enabled: bool = True


class ScheduleOut(ScheduleIn):
    id: int
    last_run_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# ---------- 检索 ----------
class SearchHit(BaseModel):
    device_name: str
    command: str
    snippet: str
    task_id: int
