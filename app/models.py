"""SQLAlchemy 数据模型。"""
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base


class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    username = Column(String(100), nullable=False)
    password_enc = Column(Text, nullable=False)
    enable_password_enc = Column(Text, default="")
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.now)

    devices = relationship("Device", back_populates="credential")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)   # 设备名（用于目录名）
    host = Column(String(255), nullable=False)
    port = Column(Integer, default=22)
    protocol = Column(String(10), default="ssh")              # ssh / telnet
    device_type = Column(String(50), default="huawei")        # netmiko driver
    group_name = Column(String(100), default="默认")
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    snmp_profile_id = Column(Integer, ForeignKey("snmp_profiles.id"), nullable=True)
    description = Column(String(255), default="")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)

    credential = relationship("Credential", back_populates="devices")
    snmp_profile = relationship("SnmpProfile")


class SnmpProfile(Base):
    """SNMP 模板（v2c community / v3 用户），凭据式复用。"""
    __tablename__ = "snmp_profiles"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    version = Column(String(10), default="v2c")               # v2c / v3
    port = Column(Integer, default=161)
    community_enc = Column(Text, default="")
    v3_user = Column(String(100), default="")
    v3_auth_key_enc = Column(Text, default="")
    v3_priv_key_enc = Column(Text, default="")
    v3_auth_proto = Column(String(10), default="MD5")         # MD5 / SHA
    v3_priv_proto = Column(String(10), default="DES")         # DES / AES
    description = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.now)


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    status = Column(String(20), default="pending")  # pending/running/done/cancelled
    commands = Column(Text, nullable=False)          # JSON: ["display version", ...]
    created_at = Column(DateTime, default=datetime.now)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    total = Column(Integer, default=0)
    success = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    trigger = Column(String(20), default="manual")   # manual / schedule

    results = relationship(
        "TaskResult", back_populates="task", cascade="all, delete-orphan"
    )


class TaskResult(Base):
    __tablename__ = "task_results"

    id = Column(Integer, primary_key=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False)
    device_id = Column(Integer, nullable=True)
    device_name = Column(String(100), nullable=False)
    status = Column(String(20), default="pending")  # pending/running/success/failed
    error = Column(Text, default="")
    output_dir = Column(String(500), default="")
    has_change = Column(Boolean, default=False)     # 与上一版相比配置有变化
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    task = relationship("Task", back_populates="results")


class CommandLog(Base):
    """命令审计日志（终端 + 任务执行的所有命令）。"""
    __tablename__ = "command_logs"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.now)
    source = Column(String(20), nullable=False)      # terminal / task
    device_name = Column(String(100), nullable=False)
    command = Column(Text, nullable=False)
    allowed = Column(Boolean, default=True)
    mode = Column(String(10), default="collect")


class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    cron = Column(String(100), nullable=False)       # 5 段 cron 表达式
    commands = Column(Text, nullable=False)          # JSON
    device_group = Column(String(100), default="")   # 空 = 全部启用设备
    enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)


class MetricSample(Base):
    """每轮监控的采样数据（每设备每轮一行）。"""
    __tablename__ = "metric_samples"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.now, index=True)
    device_name = Column(String(100), nullable=False, index=True)
    online = Column(Boolean, default=False)
    latency_ms = Column(Integer, nullable=True)      # TCP 连接耗时
    cpu_pct = Column(Integer, nullable=True)         # 0-100
    mem_pct = Column(Integer, nullable=True)         # 0-100
    temperature = Column(Float, nullable=True)       # 板卡最高温 ℃（SNMP 私有 OID）
    if_up = Column(Integer, nullable=True)           # up 接口数
    if_down = Column(Integer, nullable=True)         # down 接口数
    if_down_names = Column(Text, default="")         # down 接口名，逗号分隔


class Alert(Base):
    """监控告警。"""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.now)
    device_name = Column(String(100), nullable=False)
    level = Column(String(10), nullable=False)       # critical / warning / info
    type = Column(String(20), nullable=False)        # offline / cpu / mem / interface
    message = Column(Text, nullable=False)
    acknowledged = Column(Boolean, default=False)


class IfaceSample(Base):
    """整机流量采样（up 物理口聚合，每轮一行）。"""
    __tablename__ = "iface_samples"

    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.now, index=True)
    device_name = Column(String(100), nullable=False, index=True)
    in_bps = Column(BigInteger, nullable=True)       # bit/s（差值/间隔）
    out_bps = Column(BigInteger, nullable=True)
    err_in = Column(Integer, nullable=True)          # 本轮错包增量
    err_out = Column(Integer, nullable=True)
    in_octets = Column(BigInteger, nullable=True)    # 原始计数器（算差值用）
    out_octets = Column(BigInteger, nullable=True)


class DeviceAsset(Base):
    """设备资产信息（SNMP 定期刷新）。"""
    __tablename__ = "device_assets"

    id = Column(Integer, primary_key=True)
    device_name = Column(String(100), unique=True, nullable=False)
    sys_descr = Column(Text, default="")
    sys_name = Column(String(255), default="")
    sys_object_id = Column(String(255), default="")
    version = Column(String(120), default="")
    uptime_days = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=datetime.now)
