from ipsources.abuseipdb import AbuseIPDBSource
from ipsources.ipapi import IpApiSource
from ipsources.ipqualityscore import IPQualityScoreSource
from ipsources.ipwhois import IpWhoIsSource

ALL_SOURCES = [
    IpWhoIsSource(),
    IpApiSource(),
    AbuseIPDBSource(),
    IPQualityScoreSource(),
]
