from datetime import datetime

from django.db import models
# Create your models here.


class RecentScansDB(models.Model):
    ANALYZER = models.CharField(max_length=50, default='')
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    VERSION_NAME = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    TIMESTAMP = models.DateTimeField(default=datetime.now)


class StaticAnalyzerAndroid(models.Model):
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=255, default='')
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='', primary_key=True)
    SHA1 = models.CharField(max_length=40, default='')
    SHA256 = models.CharField(max_length=64, default='')
    PACKAGE_NAME = models.TextField(default='')
    MAIN_ACTIVITY = models.TextField(default='')
    EXPORTED_ACTIVITIES = models.TextField(default='')
    BROWSABLE_ACTIVITIES = models.TextField(default={})
    ACTIVITIES = models.TextField(default=[])
    RECEIVERS = models.TextField(default=[])
    PROVIDERS = models.TextField(default=[])
    SERVICES = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    TARGET_SDK = models.CharField(max_length=50, default='')
    MAX_SDK = models.CharField(max_length=50, default='')
    MIN_SDK = models.CharField(max_length=50, default='')
    VERSION_NAME = models.CharField(max_length=100, default='')
    VERSION_CODE = models.CharField(max_length=50, default='')
    ICON_PATH = models.TextField(default='')
    PERMISSIONS = models.TextField(default={})
    MALWARE_PERMISSIONS = models.TextField(default={})
    CERTIFICATE_ANALYSIS = models.TextField(default={})
    MANIFEST_ANALYSIS = models.TextField(default=[])
    BINARY_ANALYSIS = models.TextField(default=[])
    FILE_ANALYSIS = models.TextField(default=[])
    ANDROID_API = models.TextField(default={})
    CODE_ANALYSIS = models.TextField(default={})
    NIAP_ANALYSIS = models.TextField(default={})
    PERMISSION_MAPPING = models.TextField(default={})
    URLS = models.TextField(default=[])
    DOMAINS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    STRINGS = models.TextField(default={})
    FIREBASE_URLS = models.TextField(default=[])
    FILES = models.TextField(default=[])
    EXPORTED_COUNT = models.TextField(default={})
    APKID = models.TextField(default={})
    QUARK = models.TextField(default=[])
    TRACKERS = models.TextField(default={})
    PLAYSTORE_DETAILS = models.TextField(default={})
    NETWORK_SECURITY = models.TextField(default=[])
    SECRETS = models.TextField(default=[])

class SuppressFindings(models.Model):
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    SUPPRESS_RULE_ID = models.TextField(default=[])
    SUPPRESS_FILES = models.TextField(default={})
    SUPPRESS_TYPE = models.TextField(default='')
