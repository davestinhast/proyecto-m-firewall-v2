APP_NAME = "M-FIREWALL"
APP_VERSION = "2.0-clean"

BASE_DIR = "/opt/proyecto-m-clean"
CONFIG_FILE = f"{BASE_DIR}/config/firewall.json"
RULES_FILE = f"{BASE_DIR}/rules/project_m.rules.v4"
IPSET_FILE = f"{BASE_DIR}/rules/project_m.ipset"
DNSMASQ_FILE = "/etc/dnsmasq.d/proyecto-m-youtube.conf"
LOG_FILE = "/var/log/proyecto-m-clean/rejected.log"
HOSTS_MARKER_BEGIN = "# BEGIN M-FIREWALL-CLEAN"
HOSTS_MARKER_END = "# END M-FIREWALL-CLEAN"

CHAIN_REJECT = "PM_REJECT"
CHAIN_WEB = "PM_WEBBLOCK"
CHAIN_CLISRV = "PM_CLISRV"
CHAIN_MAC = "PM_MACBLOCK"
CHAIN_CONNLIMIT = "PM_CONNLIMIT"
IPSET_PREFIX = "PM_"

SITES = {
    "facebook": {
        "label": "Facebook",
        "domains": ["facebook.com", "www.facebook.com", "m.facebook.com", "fbcdn.net", "fb.com", "messenger.com"],
        "keywords": ["facebook", "fbcdn", "fb.com", "messenger"],
    },
    "hotmail": {
        "label": "Hotmail / Outlook",
        "domains": ["hotmail.com", "outlook.com", "outlook.live.com", "login.live.com", "live.com"],
        "keywords": ["hotmail", "outlook", "live.com"],
    },
    "youtube": {
        "label": "YouTube",
        "domains": [
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "youtu.be",
            "youtube-nocookie.com",
            "googlevideo.com",
            "ytimg.com",
            "yt3.ggpht.com",
            "ggpht.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "youtube.l.google.com",
            "youtube-ui.l.google.com",
            "ytstatic.l.google.com",
        ],
        "keywords": ["youtube", "youtu", "googlevideo", "ytimg", "ggpht", "youtubei", "ytstatic"],
    },
}
