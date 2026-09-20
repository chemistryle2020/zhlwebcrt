"""监控引擎：定时探测设备在线状态 + CPU/内存/接口指标，产生告警。

每轮流程：TCP 探测（在线/时延）→ 在线则 Netmiko 采集指标 → 存采样 →
与上一次采样对比产生告警（离线/恢复/超阈值/接口 down 增加）。
所有解析器宽容失败：解析不出存 None，绝不影响整轮。
"""
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from netmiko import ConnectHandler

from ..config import get_settings
from ..database import SessionLocal
from ..models import Alert, Device, IfaceSample, MetricSample
from . import cmdfilter, snmp
from .collector import decrypt

_round_lock = threading.Lock()
RETENTION_DAYS = 7


# ---------- 指标解析器（全部宽容失败） ----------

def _pct(s: str) -> int | None:
    try:
        return max(0, min(100, round(float(s))))
    except (ValueError, TypeError):
        return None


def parse_zte(cpu_out: str, _mem_out: str) -> tuple[int | None, int | None]:
    """中兴 show processor：一行内含 CPU(5s) CPU(1m) CPU(5m) Peak PhyMem FreeMem Mem"""
    m = re.search(
        r"(\d+)%\s+(\d+)%\s+(\d+)%\s+\d+%\s+\d+\s+\d+\s+([\d.]+)%", cpu_out
    )
    if m:
        return _pct(m.group(2)), _pct(m.group(4))  # CPU(1m), Mem
    return None, None


def parse_huawei(cpu_out: str, mem_out: str) -> tuple[int | None, int | None]:
    cpu = mem = None
    m = re.search(r"CPU Usage\s*[:：]\s*(\d+)%", cpu_out, re.I)
    if m:
        cpu = _pct(m.group(1))
    else:
        m = re.search(r"CPU utilization (?:for|is).*?(\d+)%", cpu_out, re.I | re.S)
        if m:
            cpu = _pct(m.group(1))
    m = re.search(r"(?:Memory (?:Using|Usage)|System Memory).*?[:：]?\s*(\d+)%", mem_out, re.I)
    if m:
        mem = _pct(m.group(1))
    return cpu, mem


def parse_cisco(cpu_out: str, mem_out: str) -> tuple[int | None, int | None]:
    cpu = mem = None
    m = re.search(r"CPU utilization for five seconds:\s*(\d+)%", cpu_out)
    if m:
        cpu = _pct(m.group(1))
    m = re.search(r"Processor Pool Total:\s*(\d+)\s+Used:\s*(\d+)", mem_out)
    if m and int(m.group(1)) > 0:
        mem = _pct(int(m.group(2)) / int(m.group(1)) * 100)
    return cpu, mem


def parse_linux(cpu_out: str, mem_out: str) -> tuple[int | None, int | None]:
    cpu = mem = None
    m = re.search(r"([\d.]+)\s*%?\s*id\b", cpu_out)  # top: %Cpu(s): ... id
    if m:
        cpu = _pct(100 - float(m.group(1)))
    m = re.search(r"Mem:\s+(\d+)\s+(\d+)", mem_out)  # free -m
    if m and int(m.group(1)) > 0:
        mem = _pct(int(m.group(2)) / int(m.group(1)) * 100)
    return cpu, mem


IF_NAME_RE = re.compile(
    r"^(?:xxvgei|xgige|gei|ge-|gigabit|eth-trunk|eth|xgigabitethernet|"
    r"gigabitethernet|xge|ge\d|te\d|fe|po\d|vlan|loop|mgmt|serial|null|"
    r"bundle-ether|port-channel)",
    re.I,
)


def parse_interfaces(brief_out: str) -> tuple[int, int, list[str]]:
    """从 *interface brief* 输出统计 up/down 接口数和 down 接口名。"""
    up = down = 0
    down_names: list[str] = []
    for line in brief_out.splitlines():
        tokens = line.split()
        if len(tokens) < 2 or not IF_NAME_RE.match(tokens[0]):
            continue
        status = [t.lower() for t in tokens[1:] if t.lower() in ("up", "down")]
        if not status:
            continue
        if "down" in status:
            down += 1
            down_names.append(tokens[0])
        else:
            up += 1
    return up, down, down_names


# 各厂商的监控命令与解析器
FAMILIES = {
    "zte": {
        "cpu_cmd": "show processor",
        "mem_cmd": None,  # 内存与 CPU 同一条命令输出
        "if_cmd": "show ip interface brief",
        "parse": parse_zte,
    },
    "huawei": {
        "cpu_cmd": "display cpu-usage",
        "mem_cmd": "display memory-usage",
        "if_cmd": "display interface brief",
        "parse": parse_huawei,
    },
    "cisco": {
        "cpu_cmd": "show processes cpu",
        "mem_cmd": "show processes memory",
        "if_cmd": "show ip interface brief",
        "parse": parse_cisco,
    },
    "linux": {
        "cpu_cmd": "top -bn1 | grep -i 'cpu(s)'",
        "mem_cmd": "free -m",
        "if_cmd": None,
        "parse": parse_linux,
    },
}


def vendor_family(device_type: str) -> str:
    dt = (device_type or "").lower()
    if dt.startswith("zte"):
        return "zte"
    if dt.startswith(("huawei", "hp_comware", "h3c")):
        return "huawei"
    if dt.startswith("cisco"):
        return "cisco"
    if dt == "linux":
        return "linux"
    return "huawei"  # 默认按 display 系尝试


# ---------- 探测与采集 ----------

def probe_tcp(host: str, port: int, timeout: float = 5.0) -> tuple[bool, int | None]:
    """TCP 连接探测：返回 (在线, 时延ms)。无需 root，Windows 可用。"""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.monotonic() - start) * 1000)
    except OSError:
        return False, None


def _collect_metrics(dev: dict, cred: dict, family_cfg: dict) -> dict:
    """SSH 采集 CPU/内存/接口指标。任何异常都容忍，返回部分数据。"""
    metrics = {"cpu": None, "mem": None, "if_up": None, "if_down": None,
               "if_down_names": []}
    conn = None
    try:
        params = {
            "device_type": dev["device_type"],
            "host": dev["host"],
            "port": dev["port"],
            "username": cred["username"],
            "password": cred["password"],
            "conn_timeout": 8,
            "read_timeout_override": 15,
        }
        if dev["protocol"] == "telnet" and not dev["device_type"].endswith("_telnet"):
            params["device_type"] += "_telnet"
        conn = ConnectHandler(**params)
        if cred.get("enable"):
            try:
                conn.enable()
            except Exception:
                pass

        cpu_out = mem_out = ""
        if family_cfg["cpu_cmd"]:
            cmdfilter.audit("monitor", dev["name"], family_cfg["cpu_cmd"], True)
            cpu_out = conn.send_command(family_cfg["cpu_cmd"], read_timeout=15)
        if family_cfg["mem_cmd"]:
            cmdfilter.audit("monitor", dev["name"], family_cfg["mem_cmd"], True)
            mem_out = conn.send_command(family_cfg["mem_cmd"], read_timeout=15)
        try:
            metrics["cpu"], metrics["mem"] = family_cfg["parse"](cpu_out, mem_out)
        except Exception:
            pass

        if family_cfg["if_cmd"]:
            cmdfilter.audit("monitor", dev["name"], family_cfg["if_cmd"], True)
            try:
                brief = conn.send_command(family_cfg["if_cmd"], read_timeout=15)
                up, down, names = parse_interfaces(brief)
                metrics["if_up"], metrics["if_down"], metrics["if_down_names"] = (
                    up, down, names,
                )
            except Exception:
                pass
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass
    return metrics


def _raise_alert(db, device_name: str, level: str, type_: str, message: str):
    """写告警；同设备同类型存在未确认告警时去重。"""
    exists = (
        db.query(Alert)
        .filter(Alert.device_name == device_name, Alert.type == type_,
                Alert.acknowledged.is_(False))
        .first()
    )
    if exists:
        return
    db.add(Alert(device_name=device_name, level=level, type=type_, message=message))


def _judge_alerts(db, device_name: str, prev: MetricSample | None,
                  now: MetricSample, settings: dict):
    if not now.online and (prev is None or prev.online):
        # 离线（含首次采样即离线）→ critical
        _raise_alert(db, device_name, "critical", "offline", f"{device_name} 离线（管理端口不可达）")
    if prev and not prev.online and now.online:
        # 恢复在线：自动确认旧离线告警，补一条 info
        for a in db.query(Alert).filter(
            Alert.device_name == device_name, Alert.type == "offline",
            Alert.acknowledged.is_(False),
        ):
            a.acknowledged = True
        db.add(Alert(device_name=device_name, level="info", type="offline",
                     message=f"{device_name} 恢复在线"))
    if now.online:
        if now.cpu_pct is not None and now.cpu_pct >= settings["cpu_threshold"]:
            _raise_alert(db, device_name, "warning", "cpu",
                         f"{device_name} CPU 利用率 {now.cpu_pct}%（阈值 {settings['cpu_threshold']}%）")
        if now.mem_pct is not None and now.mem_pct >= settings["mem_threshold"]:
            _raise_alert(db, device_name, "warning", "mem",
                         f"{device_name} 内存利用率 {now.mem_pct}%（阈值 {settings['mem_threshold']}%）")
        if prev and prev.if_down is not None and now.if_down is not None \
                and now.if_down > prev.if_down:
            names = "、".join(now.if_down_names[:5])
            _raise_alert(db, device_name, "warning", "interface",
                         f"{device_name} down 接口数 {prev.if_down} → {now.if_down}（{names}）")


def _snmp_profile_dict(p) -> dict:
    """SnmpProfile ORM → 解密后的 profile dict。"""
    return {
        "version": p.version,
        "port": p.port,
        "community": decrypt(p.community_enc),
        "v3_user": p.v3_user,
        "v3_auth_key": decrypt(p.v3_auth_key_enc),
        "v3_priv_key": decrypt(p.v3_priv_key_enc),
        "v3_auth_proto": p.v3_auth_proto,
        "v3_priv_proto": p.v3_priv_proto,
    }


def _refresh_asset(db, dev: dict, snmp_profile: dict):
    """资产信息每日刷新一次。"""
    from ..models import DeviceAsset

    asset = (
        db.query(DeviceAsset)
        .filter(DeviceAsset.device_name == dev["name"])
        .first()
    )
    if asset and asset.updated_at and \
            (datetime.now() - asset.updated_at) < timedelta(hours=24):
        return
    info = snmp.get_asset(snmp_profile, dev["host"])
    if not info:
        return
    if not asset:
        asset = DeviceAsset(device_name=dev["name"])
        db.add(asset)
    asset.sys_descr = info["sys_descr"]
    asset.sys_name = info["sys_name"]
    asset.sys_object_id = info["sys_object_id"]
    asset.version = info["version"]
    asset.uptime_days = info["uptime_days"]
    asset.updated_at = datetime.now()


def _monitor_one(dev: dict, settings: dict):
    snmp_prof = dev.get("snmp")
    snmp_ok = False
    totals = None
    online, latency = False, None

    # 1) SNMP 优先探测
    if snmp_prof:
        try:
            online, latency = snmp.probe(snmp_prof, dev["host"], timeout=5)
            snmp_ok = online
        except Exception:  # noqa: BLE001
            online, latency = False, None
    # 2) TCP 兜底探测
    if not online:
        online, latency = probe_tcp(dev["host"], dev["port"])

    metrics = {"cpu": None, "mem": None, "if_up": None, "if_down": None,
               "if_down_names": [], "temp": None, "temp_over": False}
    family = vendor_family(dev["device_type"])
    vendor_oids = snmp.VENDOR_OIDS.get(family)

    if snmp_ok:
        # 3) SNMP 采集：接口状态 + 流量计数器
        try:
            interfaces = snmp.get_interfaces(snmp_prof, dev["host"])
            if interfaces:
                metrics["if_up"] = sum(1 for i in interfaces if i["oper"] == "up")
                downs = [i for i in interfaces if i["oper"] == "down"]
                metrics["if_down"] = len(downs)
                metrics["if_down_names"] = [i["name"] for i in downs]
                totals = snmp.traffic_totals(interfaces)
        except Exception:  # noqa: BLE001
            pass
        # 4) CPU/内存/温度：中兴走私有 OID 表（5960X 等 ZXR10 平台）
        if family == "zte":
            try:
                metrics["cpu"], metrics["mem"] = \
                    snmp.get_zte_cpu_mem(snmp_prof, dev["host"])
            except Exception:  # noqa: BLE001
                pass
            try:
                t = snmp.get_zte_temperature(snmp_prof, dev["host"])
                if t:
                    metrics["temp"] = t["temperature"]
                    metrics["temp_over"] = t["over_threshold"]
            except Exception:  # noqa: BLE001
                pass
        elif vendor_oids:
            try:
                r = snmp.snmp_get(snmp_prof, dev["host"],
                                  [vendor_oids["cpu"], vendor_oids["mem"]])
                if r:
                    metrics["cpu"] = _pct(r.get(vendor_oids["cpu"]))
                    metrics["mem"] = _pct(r.get(vendor_oids["mem"]))
            except Exception:  # noqa: BLE001
                pass

    # 5) SSH 兜底：SNMP 不可用（全量回退），或 SNMP 可取但厂商 OID 未配置（补 CPU/内存）
    if online and dev.get("cred") and (not snmp_ok or metrics["cpu"] is None):
        try:
            family_cfg = FAMILIES[family]
            m = _collect_metrics(dev, dev["cred"], family_cfg)
            if metrics["cpu"] is None:
                metrics["cpu"] = m["cpu"]
            if metrics["mem"] is None:
                metrics["mem"] = m["mem"]
            if not snmp_ok:
                metrics["if_up"] = m["if_up"]
                metrics["if_down"] = m["if_down"]
                metrics["if_down_names"] = m["if_down_names"]
        except Exception:  # noqa: BLE001
            pass

    now = datetime.now()
    with SessionLocal() as db:
        prev = (
            db.query(MetricSample)
            .filter(MetricSample.device_name == dev["name"])
            .order_by(MetricSample.id.desc())
            .first()
        )
        sample = MetricSample(
            device_name=dev["name"], online=online, latency_ms=latency,
            cpu_pct=metrics["cpu"], mem_pct=metrics["mem"],
            temperature=metrics["temp"],
            if_up=metrics["if_up"], if_down=metrics["if_down"],
            if_down_names=",".join(metrics["if_down_names"][:20]),
        )
        db.add(sample)

        # 温度超设备门限告警（门限值存在设备侧，SNMP 直接返回越限状态）
        if online and metrics["temp_over"]:
            _raise_alert(db, dev["name"], "warning", "temp",
                         f"{dev['name']} 板卡温度 {metrics['temp']}℃ 超设备告警门限")

        # 流量采样：与上轮原始计数器差值/间隔 = bps
        if totals:
            prev_if = (
                db.query(IfaceSample)
                .filter(IfaceSample.device_name == dev["name"])
                .order_by(IfaceSample.id.desc())
                .first()
            )
            in_bps = out_bps = err_in = err_out = None
            if prev_if and prev_if.in_octets is not None:
                dt = (now - prev_if.ts).total_seconds()
                if dt > 1:
                    d_in = totals["in_octets"] - prev_if.in_octets
                    d_out = totals["out_octets"] - prev_if.out_octets
                    if d_in >= 0:  # 负数=设备重启/计数器清零，丢弃本轮
                        in_bps = int(d_in * 8 / dt)
                    if d_out >= 0:
                        out_bps = int(d_out * 8 / dt)
                    err_in = totals["err_in"] - prev_if.err_in \
                        if prev_if.err_in is not None and totals["err_in"] >= prev_if.err_in else 0
                    err_out = totals["err_out"] - prev_if.err_out \
                        if prev_if.err_out is not None and totals["err_out"] >= prev_if.err_out else 0
            db.add(IfaceSample(
                device_name=dev["name"], in_bps=in_bps, out_bps=out_bps,
                err_in=err_in, err_out=err_out,
                in_octets=totals["in_octets"], out_octets=totals["out_octets"],
            ))

        # 资产每日刷新
        if snmp_ok:
            try:
                _refresh_asset(db, dev, snmp_prof)
            except Exception:  # noqa: BLE001
                pass

        _judge_alerts(db, dev["name"], prev, sample, settings)
        db.commit()


def run_round():
    """执行一轮监控（幂等防重入）。"""
    settings = get_settings()
    if not settings.get("monitor_enabled", True):
        return
    if not _round_lock.acquire(blocking=False):
        return
    try:
        with SessionLocal() as db:
            devices = db.query(Device).filter(Device.enabled.is_(True)).all()
            dev_list = [
                {
                    "name": d.name, "host": d.host, "port": d.port,
                    "protocol": d.protocol, "device_type": d.device_type,
                    "cred": (
                        {
                            "username": d.credential.username,
                            "password": decrypt(d.credential.password_enc),
                            "enable": decrypt(d.credential.enable_password_enc),
                        }
                        if d.credential else None
                    ),
                    "snmp": _snmp_profile_dict(d.snmp_profile) if d.snmp_profile else None,
                }
                for d in devices
            ]
        if not dev_list:
            return
        with ThreadPoolExecutor(max_workers=settings["concurrency"]) as pool:
            futures = [pool.submit(_monitor_one, d, settings) for d in dev_list]
            for f in futures:
                try:
                    f.result()
                except Exception:
                    pass
        # 清理历史数据
        cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
        with SessionLocal() as db:
            db.query(MetricSample).filter(MetricSample.ts < cutoff).delete()
            db.query(IfaceSample).filter(IfaceSample.ts < cutoff).delete()
            db.query(Alert).filter(Alert.ts < cutoff, Alert.acknowledged.is_(True)).delete()
            db.commit()
    finally:
        _round_lock.release()


def latest_status() -> list[dict]:
    """每台启用设备的最新状态（overview 用）。"""
    with SessionLocal() as db:
        devices = db.query(Device).filter(Device.enabled.is_(True)).all()
        result = []
        for d in devices:
            s = (
                db.query(MetricSample)
                .filter(MetricSample.device_name == d.name)
                .order_by(MetricSample.id.desc())
                .first()
            )
            tr = (
                db.query(IfaceSample)
                .filter(IfaceSample.device_name == d.name)
                .order_by(IfaceSample.id.desc())
                .first()
            )
            result.append({
                "device_id": d.id,
                "device_name": d.name,
                "host": d.host,
                "group_name": d.group_name,
                "device_type": d.device_type,
                "has_snmp": d.snmp_profile_id is not None,
                "online": s.online if s else None,
                "latency_ms": s.latency_ms if s else None,
                "cpu_pct": s.cpu_pct if s else None,
                "mem_pct": s.mem_pct if s else None,
                "temperature": s.temperature if s else None,
                "if_up": s.if_up if s else None,
                "if_down": s.if_down if s else None,
                "if_down_names": s.if_down_names if s else "",
                "in_bps": tr.in_bps if tr else None,
                "out_bps": tr.out_bps if tr else None,
                "last_seen": s.ts.isoformat() if s else None,
            })
        return result
