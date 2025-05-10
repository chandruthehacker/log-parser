from . import apache
from . import nginx
from . import syslog
from . import authlog

# You can expand this list as you add more log types
log_modules = {
    'apache': apache,
    'nginx': nginx,
    'syslog': syslog,
    'authlog': authlog,
}

