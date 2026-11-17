import re
from datetime import datetime, timezone

SOURCES = [
    "auth", "syslog", "mail", "daemon", "user", "exim", "apache_access",
    "apache_error", "suricata_fast", "suricata_eve", "audit",
]

FILENAME_RULES = [
    (re.compile(r"access\.log$"), "apache_access"),
    (re.compile(r"error\.log$"), "apache_error"),
    (re.compile(r"(^|/)audit\.log$"), "audit"),
    (re.compile(r"(^|/)auth\.log$"), "auth"),
    (re.compile(r"(^|/)syslog$"), "syslog"),
    (re.compile(r"(^|/)mail\.log$"), "mail"),
    (re.compile(r"(^|/)daemon\.log$"), "daemon"),
    (re.compile(r"(^|/)user\.log$"), "user"),
    (re.compile(r"(^|/)mainlog$"), "exim"),
    (re.compile(r"(^|/)fast\.log$"), "suricata_fast"),
    (re.compile(r"(^|/)eve\.json$"), "suricata_eve"),
]

MAX_CHARS = 512

TS_RE = re.compile("|".join([
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?",
    r"\b\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    r"\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]",
    r"\[\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}\]",
    r"^\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}",
    r"audit\(\d+\.\d+:\d+\)",
    r"\b\d{8}\d{6}\b",
]))
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
FLOW_RE = re.compile(r'"flow_id":\d+')
HEX_RE = re.compile(r"\b(proctitle|cmd)=([0-9A-F]{8,})\b")
AUDIT_MASK_RE = re.compile(r"\b(pid|ppid|ses|auid|inode|a[0-3]|item|items)=[0-9a-fx]+")
SYSCALL_FIELDS_RE = re.compile(r' ppid=(\d+) pid=(\d+) .*? uid=(\d+) .*? comm="([^"]*)"')
SERIAL_RE = re.compile(r"msg=audit\(\d+\.\d+:(\d+)\)")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def detect_source(path):
    p = str(path).replace("\\", "/")
    for rx, src in FILENAME_RULES:
        if rx.search(p):
            return src
    return None


def host_regex(hostnames):
    parts = [r"\bmail-\d+\b"]
    for h in hostnames:
        h = h.strip()
        if h:
            parts.append(r"\b(?:mail\.)?" + re.escape(h) + r"\b")
    return re.compile("|".join(parts))


def _unhex(m):
    try:
        return f'{m[1]}="{bytes.fromhex(m[2]).decode("utf-8", "replace").replace(chr(0), " ")}"'
    except ValueError:
        return m[0]


class Normalizer:
    def __init__(self, hostnames, default_year):
        self.host_re = host_regex(hostnames)
        self.default_year = default_year
        self.ts_parse = [
            (re.compile(r"audit\((\d+\.\d+):"), lambda m: datetime.fromtimestamp(float(m[1]), timezone.utc)),
            (re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"),
             lambda m: datetime(*map(int, m.groups()), tzinfo=timezone.utc)),
            (re.compile(r"(\d{2})/(\d{2})/(\d{4})-(\d{2}):(\d{2}):(\d{2})"),
             lambda m: datetime(int(m[3]), int(m[1]), int(m[2]), int(m[4]), int(m[5]), int(m[6]), tzinfo=timezone.utc)),
            (re.compile(r"\[(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})"),
             lambda m: datetime(int(m[3]), MONTHS[m[2]], int(m[1]), int(m[4]), int(m[5]), int(m[6]), tzinfo=timezone.utc)),
            (re.compile(r"\[\w{3} (\w{3}) (\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]"),
             lambda m: datetime(int(m[6]), MONTHS[m[1]], int(m[2]), int(m[3]), int(m[4]), int(m[5]), tzinfo=timezone.utc)),
            (re.compile(r"^(\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})"),
             lambda m: datetime(self.default_year, MONTHS[m[1]], int(m[2]), int(m[3]), int(m[4]), int(m[5]),
                                tzinfo=timezone.utc)),
        ]

    def timestamp(self, line):
        head = line[:200]
        for rx, fn in self.ts_parse:
            m = rx.search(head)
            if m:
                try:
                    return fn(m).timestamp()
                except (ValueError, KeyError):
                    return None
        return None

    def text(self, line, audit=False):
        if audit:
            line = AUDIT_MASK_RE.sub(r"\1=*", line)
        line = HEX_RE.sub(_unhex, line)
        line = TS_RE.sub("<TS>", line)
        line = FLOW_RE.sub('"flow_id":<ID>', line)
        line = IP_RE.sub("<IP>", line)
        line = self.host_re.sub("<HOST>", line)
        return line[:MAX_CHARS]


class AuditTracker:
    def __init__(self):
        self.procs = {}
        self.serial, self.tag = None, "[ev ?]"

    def annotate(self, line):
        m = SERIAL_RE.search(line)
        serial = m[1] if m else None
        if line.startswith("type=SYSCALL"):
            f = SYSCALL_FIELDS_RE.search(line)
            if f:
                ppid, pid, uid, comm = f.groups()
                self.procs[pid] = (comm, ppid)
                pcomm, gppid = self.procs.get(ppid, ("?", None))
                gpcomm = self.procs.get(gppid, ("?", None))[0] if gppid else "?"
                self.serial, self.tag = serial, f"[ev comm={comm} uid={uid} pcomm={pcomm} gpcomm={gpcomm}]"
                return self.tag
        return self.tag if serial is not None and serial == self.serial else "[ev ?]"
