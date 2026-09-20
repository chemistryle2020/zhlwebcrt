"""SNMP v2c/v3 采集：get/walk 基础 + OID 映射 + 表格解析。

纯 Python（pysnmp），Windows 可用。敏感字段（community/密钥）在
SnmpProfile 里加密存储，调用前由调用方解密后放入 profile dict。
"""
import ipaddress
import logging
import re
import time

from pysnmp.hlapi import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    getCmd,
    nextCmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

logger = logging.getLogger("zhlwebcrt.snmp")

# ---------- 标准 OID ----------
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# ifTable / ifXTable
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_PHYS_ADDR = "1.3.6.1.2.1.2.2.1.6"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_HC_IN = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# 表格
OID_ARP_IFINDEX = "1.3.6.1.2.1.4.22.1.1"
OID_ARP_MAC = "1.3.6.1.2.1.4.22.1.2"
OID_ARP_IP = "1.3.6.1.2.1.4.22.1.3"
OID_MAC_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"
OID_MAC_STATUS = "1.3.6.1.2.1.17.7.1.2.2.1.3"
OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"

# 厂商私有 CPU/内存 OID（标量 get 型，取值失败时 monitor 自动回退 SSH 解析）
VENDOR_OIDS: dict[str, dict] = {
    # "cisco": {"cpu": "1.3.6.1.4.1.9.x...", "mem": "1.3.6.1.4.1.9.x..."},
}

# ---------- 中兴 ZXR10 私有 OID ----------
# 来源：ZXR10 5960X V6.00.04.20P01 MIB 清单（SUP 平台 ZXR10-SYSTEM-HARDWARE-MIB /
# ZXR10-OPTICAL-MIB）。CPU/内存为表结构（索引 {rack,shelf,slot,unit}），
# 整机指标取所有处理单元的最大值。
ZTE_CPU_ENTRY = "1.3.6.1.4.1.3902.3.6002.2.1.1"      # zxr10CpusystemEntry
ZTE_CPU_1M = ZTE_CPU_ENTRY + ".8"                    # CPU 1 分钟利用率 %
ZTE_CPU_5M = ZTE_CPU_ENTRY + ".9"                    # CPU 5 分钟利用率 %
ZTE_MEM_SIZE = ZTE_CPU_ENTRY + ".5"                  # 物理内存大小
ZTE_MEM_USED = ZTE_CPU_ENTRY + ".6"                  # 内存已用（单位随版本，见下方处理）
ZTE_MEM_FREE = ZTE_CPU_ENTRY + ".33"                 # 单板剩余内存
ZTE_MEM_USED_EX = ZTE_CPU_ENTRY + ".34"              # 单板已用内存

ZTE_BOARD_TEMP_ENTRY = "1.3.6.1.4.1.3902.3.6002.2.5.1"   # zxr10BoardTempEntry
ZTE_BOARD_TEMP_BOARD = ZTE_BOARD_TEMP_ENTRY + ".6"       # 单板名称
ZTE_BOARD_TEMP_DESC = ZTE_BOARD_TEMP_ENTRY + ".7"        # 测温点描述
ZTE_BOARD_TEMP_CUR = ZTE_BOARD_TEMP_ENTRY + ".9"         # 当前温度 ℃
ZTE_BOARD_TEMP_MAJOR = ZTE_BOARD_TEMP_ENTRY + ".11"      # 中门限 ℃

ZTE_FAN_ENTRY = "1.3.6.1.4.1.3902.3.6002.2.3.1"          # zxr10FanEntry
ZTE_FAN_POSITION = ZTE_FAN_ENTRY + ".22"                  # 位置名（FAN1/FAN2...）
ZTE_FAN_STATUS = ZTE_FAN_ENTRY + ".7"                     # 风扇状态
ZTE_FAN_SPEED = ZTE_FAN_ENTRY + ".8"                      # 转速等级
ZTE_FAN_RATIO = ZTE_FAN_ENTRY + ".14"                     # 占空比%(128≈auto)

ZTE_POWER_ENTRY = "1.3.6.1.4.1.3902.3.6002.2.6.2.1"      # zxr10PowerModuleEntry
ZTE_POWER_PHY_STATUS = ZTE_POWER_ENTRY + ".4"            # 在位状态
ZTE_POWER_RUN_STATUS = ZTE_POWER_ENTRY + ".7"            # 运行状态
ZTE_POWER_NAME = ZTE_POWER_ENTRY + ".13"                 # 型号名称
ZTE_POWER_CAPACITY = ZTE_POWER_ENTRY + ".16"             # 功率容量（字符串如 "550.00W"）
ZTE_POWER_USED = ZTE_POWER_ENTRY + ".17"                 # 已用功率（字符串如 "66.12W"）
ZTE_POWER_POSITION = ZTE_POWER_ENTRY + ".27"             # 位置名（PWR1/PWR2）

# 光模块诊断表（索引为接口名字符串 {zxr10OpticalIfName}）
ZTE_OPT_ENTRY = "1.3.6.1.4.1.3902.3.103.11.1.1"
ZTE_OPT_WAVELENGTH = ZTE_OPT_ENTRY + ".16"   # 波长
ZTE_OPT_RX = ZTE_OPT_ENTRY + ".18"           # 收光 dBm
ZTE_OPT_RX_VALID = ZTE_OPT_ENTRY + ".19"
ZTE_OPT_TX = ZTE_OPT_ENTRY + ".20"           # 发光 dBm
ZTE_OPT_TX_VALID = ZTE_OPT_ENTRY + ".21"
ZTE_OPT_CURRENT = ZTE_OPT_ENTRY + ".22"      # 偏置电流 mA
ZTE_OPT_CURRENT_VALID = ZTE_OPT_ENTRY + ".23"
ZTE_OPT_TEMP = ZTE_OPT_ENTRY + ".24"         # 温度 ℃
ZTE_OPT_TEMP_VALID = ZTE_OPT_ENTRY + ".25"
ZTE_OPT_VOLTAGE = ZTE_OPT_ENTRY + ".26"      # 电压
ZTE_OPT_VOLTAGE_VALID = ZTE_OPT_ENTRY + ".27"

IF_OPER_UP = "1"


# ---------- 会话构造 ----------

_AUTH_PROTOS = {"MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol}
_PRIV_PROTOS = {"DES": usmDESPrivProtocol, "AES": usmAesCfb128Protocol}


def _auth(profile: dict):
    if profile.get("version") == "v3":
        kwargs = {}
        auth_key = profile.get("v3_auth_key") or ""
        priv_key = profile.get("v3_priv_key") or ""
        if auth_key:
            kwargs["authKey"] = auth_key
            kwargs["authProtocol"] = _AUTH_PROTOS.get(
                profile.get("v3_auth_proto", "MD5"), usmHMACMD5AuthProtocol
            )
        else:
            kwargs["authProtocol"] = usmNoAuthProtocol
        if priv_key:
            kwargs["privKey"] = priv_key
            kwargs["privProtocol"] = _PRIV_PROTOS.get(
                profile.get("v3_priv_proto", "DES"), usmDESPrivProtocol
            )
        else:
            kwargs["privProtocol"] = usmNoPrivProtocol
        return UsmUserData(profile.get("v3_user") or "", **kwargs)
    return CommunityData(profile.get("community") or "public", mpModel=1)  # v2c


def _target(profile: dict, host: str, timeout=3, retries=1):
    return UdpTransportTarget(
        (host, int(profile.get("port") or 161)), timeout=timeout, retries=retries
    )


def _context(profile: dict) -> ContextData:
    # 真实设备用默认空上下文；模拟器/多实例设备可指定 contextName
    return ContextData(contextName=profile.get("context") or "")


# ---------- get / walk ----------

def snmp_get(profile: dict, host: str, oids: list[str],
             timeout=3) -> dict[str, str] | None:
    """取一组 OID 的值。全部失败返回 None（设备不可达/认证错误）。"""
    try:
        err_ind, err_stat, err_idx, var_binds = next(
            getCmd(
                SnmpEngine(),
                _auth(profile),
                _target(profile, host, timeout=timeout),
                _context(profile),
                *[ObjectType(ObjectIdentity(o)) for o in oids],
                lookupMib=False,
            )
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("snmp_get %s 异常: %s", host, e)
        return None
    if err_ind or err_stat:
        logger.debug("snmp_get %s 失败: %s %s", host, err_ind, err_stat)
        return None
    result = {}
    for oid, val in var_binds:
        v = val.prettyPrint()
        if "No Such" in v:
            v = ""
        result[oid.prettyPrint()] = v
    return result


def snmp_walk(profile: dict, host: str, base_oid: str,
              timeout=3) -> dict[str, str]:
    """walk 子树，返回 {完整oid: 值}（失败返回空 dict）。"""
    result = {}
    try:
        for err_ind, err_stat, err_idx, var_binds in nextCmd(
            SnmpEngine(),
            _auth(profile),
            _target(profile, host, timeout=timeout),
            _context(profile),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
            lookupMib=False,
        ):
            if err_ind or err_stat:
                break
            for oid, val in var_binds:
                result[oid.prettyPrint()] = val.prettyPrint()
    except Exception as e:  # noqa: BLE001
        logger.debug("snmp_walk %s %s 异常: %s", host, base_oid, e)
    return result


def probe(profile: dict, host: str, timeout=3) -> tuple[bool, int | None]:
    """SNMP 探测：sysUpTime 取值。返回 (在线, 耗时ms)。"""
    start = time.monotonic()
    r = snmp_get(profile, host, [OID_SYS_UPTIME], timeout=timeout)
    if r is None:
        return False, None
    return True, round((time.monotonic() - start) * 1000)


# ---------- 接口数据 ----------

def _suffix(oid: str, base: str) -> str:
    return oid[len(base) + 1:] if oid.startswith(base + ".") else oid


def get_interfaces(profile: dict, host: str) -> list[dict]:
    """接口清单：名称/状态/流量计数器/错包（按 ifIndex 合并多次 walk）。"""
    names = snmp_walk(profile, host, OID_IF_NAME) or snmp_walk(profile, host, OID_IF_DESCR)
    oper = snmp_walk(profile, host, OID_IF_OPER_STATUS)
    hc_in = snmp_walk(profile, host, OID_IF_HC_IN)
    hc_out = snmp_walk(profile, host, OID_IF_HC_OUT)
    err_in = snmp_walk(profile, host, OID_IF_IN_ERRORS)
    err_out = snmp_walk(profile, host, OID_IF_OUT_ERRORS)
    speed = snmp_walk(profile, host, OID_IF_HIGH_SPEED)
    alias = snmp_walk(profile, host, OID_IF_ALIAS)

    ifs = {}
    for base, data, key in (
        (OID_IF_NAME, names, "name"), (OID_IF_OPER_STATUS, oper, "oper"),
        (OID_IF_HC_IN, hc_in, "hc_in"), (OID_IF_HC_OUT, hc_out, "hc_out"),
        (OID_IF_IN_ERRORS, err_in, "err_in"), (OID_IF_OUT_ERRORS, err_out, "err_out"),
        (OID_IF_HIGH_SPEED, speed, "speed_m"), (OID_IF_ALIAS, alias, "alias"),
    ):
        # ifXTable walk 不到时 name 用 ifDescr 的 base
        b = base
        if base == OID_IF_NAME and not any(o.startswith(base) for o in data):
            b = OID_IF_DESCR
        for oid, val in data.items():
            idx = _suffix(oid, b)
            ifs.setdefault(idx, {})[key] = val

    result = []
    for idx, d in sorted(ifs.items(), key=lambda kv: kv[0]):
        def to_int(v):
            try:
                return int(str(v).split(" ")[0])
            except (ValueError, TypeError):
                return None
        result.append({
            "if_index": idx,
            "name": d.get("name", f"if{idx}"),
            "alias": d.get("alias", ""),
            "oper": "up" if d.get("oper") == IF_OPER_UP else "down",
            "speed_m": to_int(d.get("speed_m")),
            "hc_in": to_int(d.get("hc_in")),
            "hc_out": to_int(d.get("hc_out")),
            "err_in": to_int(d.get("err_in")) or 0,
            "err_out": to_int(d.get("err_out")) or 0,
        })
    return result


def traffic_totals(interfaces: list[dict]) -> dict:
    """整机 up 物理口流量计数器聚合（bps 由调用方用差值/间隔算）。"""
    total_in = total_out = err_in = err_out = 0
    for i in interfaces:
        if i["oper"] != "up" or i["hc_in"] is None:
            continue
        total_in += i["hc_in"] or 0
        total_out += i["hc_out"] or 0
        err_in += i["err_in"]
        err_out += i["err_out"]
    return {"in_octets": total_in, "out_octets": total_out,
            "err_in": err_in, "err_out": err_out}


# ---------- 表格采集 ----------

def _oid_to_mac(oid_suffix: str) -> str:
    """OID 后缀的 6 段十进制 → MAC 地址。"""
    parts = oid_suffix.split(".")
    if len(parts) != 6:
        return oid_suffix
    try:
        return ":".join(f"{int(p):02x}" for p in parts)
    except ValueError:
        return oid_suffix


def _pretty_mac(val: str) -> str:
    """pysnmp prettyPrint 的 MAC（可能是 hex 字符串或 0x 前缀）。"""
    v = val.strip()
    if v.startswith("0x"):
        h = v[2:]
        return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    return v


def collect_arp(profile: dict, host: str) -> list[dict]:
    """ARP 表：接口索引/IP/MAC。"""
    macs = snmp_walk(profile, host, OID_ARP_MAC)
    ifs = snmp_walk(profile, host, OID_ARP_IFINDEX)
    names = {d["if_index"]: d["name"] for d in get_interfaces(profile, host)}
    rows = []
    for oid, mac in macs.items():
        suffix = _suffix(oid, OID_ARP_MAC)  # ifIndex.ip
        parts = suffix.split(".", 1)
        if len(parts) != 2:
            continue
        if_index, ip = parts
        rows.append({
            "ip": ip,
            "mac": _pretty_mac(mac),
            "interface": names.get(if_index, if_index),
        })
    return rows


def collect_mac_table(profile: dict, host: str) -> list[dict]:
    """MAC 地址表：MAC/VLAN/端口（bridge port 映射 ifIndex）。"""
    ports = snmp_walk(profile, host, OID_MAC_PORT)
    port2if = snmp_walk(profile, host, OID_BASE_PORT_IFINDEX)
    ifnames = {d["if_index"]: d["name"] for d in get_interfaces(profile, host)}
    rows = []
    for oid, port in ports.items():
        suffix = _suffix(oid, OID_MAC_PORT)  # vlan.mac(6段)
        parts = suffix.split(".", 1)
        if len(parts) != 2:
            continue
        vlan, mac_oid = parts
        if_index = port2if.get(f"{OID_BASE_PORT_IFINDEX}.{port}", port)
        rows.append({
            "mac": _oid_to_mac(mac_oid),
            "vlan": vlan,
            "interface": ifnames.get(str(if_index), str(if_index)),
        })
    return rows


def collect_interfaces_table(profile: dict, host: str) -> list[dict]:
    """接口清单表（导出用，含速率/别名）。"""
    return [
        {
            "interface": i["name"],
            "alias": i["alias"],
            "status": i["oper"],
            "speed_mbps": i["speed_m"],
            "err_in": i["err_in"],
            "err_out": i["err_out"],
        }
        for i in get_interfaces(profile, host)
    ]


# ---------- 资产 ----------

_VERSION_RE = re.compile(r"(?:Version[:\s]*)?V\d[\w.,()\[\]/ -]*", re.I)

def get_asset(profile: dict, host: str) -> dict | None:
    """资产信息：sysDescr/sysName/sysObjectID/sysUpTime + 版本解析。"""
    r = snmp_get(profile, host,
                 [OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_UPTIME, OID_SYS_NAME])
    if r is None:
        return None
    descr = r.get(OID_SYS_DESCR, "")
    m = _VERSION_RE.search(descr.replace("\n", " "))
    uptime_ticks = r.get(OID_SYS_UPTIME, "0")
    try:
        uptime_days = round(int(str(uptime_ticks).split(" ")[0]) / 100 / 86400, 1)
    except ValueError:
        uptime_days = None
    return {
        "sys_descr": descr[:500],
        "sys_name": r.get(OID_SYS_NAME, ""),
        "sys_object_id": r.get(OID_SYS_OBJECT_ID, ""),
        "version": (m.group(0).strip(" ,") if m else "")[:100],
        "uptime_days": uptime_days,
    }


# ---------- 中兴私有采集（5960X 等 ZXR10 平台） ----------

def _to_num(val: str) -> float | None:
    """pysnmp prettyPrint 的值转数字（失败/空/NoSuch 返回 None）。"""
    v = (val or "").strip()
    if not v or "No Such" in v:
        return None
    try:
        return float(v.split(" ")[0])
    except ValueError:
        return None


def _col(walk: dict[str, str], base: str) -> dict[str, float | None]:
    """从 walk 结果里抽一列：{实例后缀: 数值}。"""
    return {
        _suffix(oid, base): _to_num(val)
        for oid, val in walk.items()
        if oid.startswith(base + ".")
    }


def get_zte_cpu_mem(profile: dict, host: str) -> tuple[float | None, float | None]:
    """整机 CPU/内存利用率 %（取所有处理单元最大值）。

    返回 (cpu_pct, mem_pct)，任一取不到为 None。
    """
    walk = snmp_walk(profile, host, ZTE_CPU_ENTRY)
    if not walk:
        return None, None

    cpu_col = _col(walk, ZTE_CPU_1M)
    cpu = max((v for v in cpu_col.values() if v is not None), default=None)

    # 内存：优先 .34 已用 + .33 剩余（同单位，百分比=used/(used+free)）
    mem_free = _col(walk, ZTE_MEM_FREE)
    mem_used = _col(walk, ZTE_MEM_USED_EX)
    mem = None
    for idx, used in mem_used.items():
        free = mem_free.get(idx)
        if used is not None and free is not None and used + free > 0:
            pct = used / (used + free) * 100
            if mem is None or pct > mem:
                mem = pct
    # 兜底：.6 已用 / .5 总量（.6 单位随版本，比值明显不合理时丢弃）
    if mem is None:
        sizes = _col(walk, ZTE_MEM_SIZE)
        useds = _col(walk, ZTE_MEM_USED)
        for idx, used in useds.items():
            size = sizes.get(idx)
            if used is not None and size and size > 0:
                pct = used / size * 100
                if 0 <= pct <= 100 and (mem is None or pct > mem):
                    mem = pct
    return (round(cpu, 1) if cpu is not None else None,
            round(mem, 1) if mem is not None else None)


def get_zte_temperature(profile: dict, host: str) -> dict | None:
    """板卡温度：返回 {temperature: 最高温℃, over_threshold: 是否超设备门限}。"""
    walk = snmp_walk(profile, host, ZTE_BOARD_TEMP_ENTRY)
    if not walk:
        return None
    cur = _col(walk, ZTE_BOARD_TEMP_CUR)
    major = _col(walk, ZTE_BOARD_TEMP_MAJOR)
    temps = [v for v in cur.values() if v is not None]
    if not temps:
        return None
    over = any(
        cur_v is not None and major_v is not None and cur_v >= major_v
        for idx, cur_v in cur.items()
        for major_v in [major.get(idx)]
    )
    return {"temperature": max(temps), "over_threshold": over}


def _decode_str_index(suffix: str) -> str:
    """字符串索引解码：首段为长度，其后各段为 ASCII 码 → 接口名。"""
    parts = suffix.split(".")
    if len(parts) < 2:
        return suffix
    try:
        n = int(parts[0])
        codes = [int(p) for p in parts[1:1 + n]]
        return bytes(codes).decode("ascii", errors="replace")
    except (ValueError, IndexError):
        return suffix


def collect_optical(profile: dict, host: str) -> list[dict]:
    """光模块诊断表：波长/收发光功率/温度/电压/偏置电流（索引为接口名字符串）。

    实测 5960 V6.00.05：walk 整表只能返回索引列（.1），数据列需逐端口 GET。
    """
    idx_walk = snmp_walk(profile, host, ZTE_OPT_ENTRY + ".1")
    suffixes = [_suffix(oid, ZTE_OPT_ENTRY + ".1") for oid in idx_walk]
    if not suffixes:
        return []

    cols = {"wavelength": 16, "rx_dbm": 18, "rx_valid": 19, "tx_dbm": 20,
            "tx_valid": 21, "current_ma": 22, "temp_c": 24, "voltage_v": 26}
    rows = []
    for sfx in sorted(suffixes, key=lambda s: [int(x) for x in s.split(".")]):
        oids = [f"{ZTE_OPT_ENTRY}.{c}.{sfx}" for c in cols.values()]
        r = snmp_get(profile, host, oids) or {}
        vals = {k: r.get(f"{ZTE_OPT_ENTRY}.{c}.{sfx}", "") for k, c in cols.items()}

        def num(key, require_valid=False):
            if require_valid and vals.get(key + "_valid", "1") != "1":
                return None
            return _to_num(vals.get(key, ""))

        rows.append({
            "interface": _decode_str_index(sfx),
            "wavelength_nm": num("wavelength"),
            "rx_dbm": num("rx_dbm", require_valid=True),
            "tx_dbm": num("tx_dbm", require_valid=True),
            "temp_c": num("temp_c"),
            "voltage_v": num("voltage_v"),
            "current_ma": num("current_ma"),
        })
    return rows


def collect_hardware(profile: dict, host: str) -> list[dict]:
    """硬件状态表：风扇 + 电源模块（每行一个部件）。"""
    rows = []

    fan_walk = snmp_walk(profile, host, ZTE_FAN_ENTRY)
    fan_pos = fan_walk and {
        _suffix(oid, ZTE_FAN_POSITION): val
        for oid, val in fan_walk.items() if oid.startswith(ZTE_FAN_POSITION + ".")
    }
    fan_status = _col(fan_walk, ZTE_FAN_STATUS)
    fan_ratio = _col(fan_walk, ZTE_FAN_RATIO)
    for idx, pos in (fan_pos or {}).items():
        st = fan_status.get(idx)
        rows.append({
            "type": "风扇",
            "position": pos,
            "status": ("正常" if st == 1.0 else f"异常({int(st)})") if st is not None else "",
            "speed": (f"{int(fan_ratio[idx])}%" if fan_ratio.get(idx) is not None
                      and fan_ratio[idx] != 128 else "auto"),
            "detail": "",
        })

    pwr_walk = snmp_walk(profile, host, ZTE_POWER_ENTRY)
    pwr_name = pwr_walk and {
        _suffix(oid, ZTE_POWER_NAME): val
        for oid, val in pwr_walk.items() if oid.startswith(ZTE_POWER_NAME + ".")
    }
    pwr_pos = pwr_walk and {
        _suffix(oid, ZTE_POWER_POSITION): val
        for oid, val in pwr_walk.items() if oid.startswith(ZTE_POWER_POSITION + ".")
    }
    pwr_cap_raw = pwr_walk and {
        _suffix(oid, ZTE_POWER_CAPACITY): val.strip()
        for oid, val in pwr_walk.items() if oid.startswith(ZTE_POWER_CAPACITY + ".")
    }
    pwr_used_raw = pwr_walk and {
        _suffix(oid, ZTE_POWER_USED): val.strip()
        for oid, val in pwr_walk.items() if oid.startswith(ZTE_POWER_USED + ".")
    }
    pwr_phy = _col(pwr_walk, ZTE_POWER_PHY_STATUS)
    pwr_run = _col(pwr_walk, ZTE_POWER_RUN_STATUS)
    for idx, name in (pwr_name or {}).items():
        phy = pwr_phy.get(idx)
        run = pwr_run.get(idx)
        if phy is not None and phy != 1.0:  # 不在位的空槽位跳过
            continue
        cap = (pwr_cap_raw or {}).get(idx, "")
        used = (pwr_used_raw or {}).get(idx, "")
        rows.append({
            "type": "电源",
            "position": (pwr_pos or {}).get(idx) or name or f"#{idx}",
            "status": ("正常" if run == 1.0 else f"异常({int(run)})") if run is not None else "",
            "speed": "",
            "detail": (f"{used}/{cap}" if used and cap else cap or ""),
        })
    return rows
