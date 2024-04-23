# -*- coding: utf_8 -*-
"""Module for network security analysis."""
import logging
from xml.dom import minidom
from pathlib import Path

from mobsf.MobSF.utils import (
    is_path_traversal,
)

logger = logging.getLogger(__name__)
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
SECURE = 'secure'


def read_netsec_config(app_dir, config, src_type):
    """Read the manifest file."""
    msg = 'Reading Network Security config'
    try:
        config_file = None
        config = config.replace('@xml/', '', 1)
        base = Path(app_dir)
        if src_type:
            # Support only android studio source files
            xml_dir = base / 'app' / 'src' / 'main' / 'res' / 'xml'
        else:
            # APK
            xml_dir = base / 'apktool_out' / 'res' / 'xml'
        if not is_path_traversal(config):
            netsec_file = xml_dir / f'{config}.xml'
            if netsec_file.exists():
                logger.info('%s from %s.xml', msg, config)
                return netsec_file.read_text('utf8', 'ignore')
        # Couldn't find the file defined in manifest
        xmls = Path(xml_dir).glob('*.xml')
        for xml in xmls:
            if 'network_security' in xml.stem:
                config_file = xml
                break
        if not config_file:
            return None
        logger.info('%s from %s', msg, config_file.name)
        return config_file.read_text('utf8', 'ignore')
    except Exception:
        logger.exception(msg)
    return None


def analysis(app_dir, config, is_debuggable, src_type):
    """Perform Network Security Analysis."""
    try:
        netsec = {
            'network_findings': [],
            'network_summary': {},
        }
        if not config:
            return netsec
        netsec_conf = read_netsec_config(app_dir, config, src_type)
        if not netsec_conf:
            return netsec
        logger.info('Parsing Network Security config')
        parsed = minidom.parseString(netsec_conf)
        finds = []
        summary = {HIGH: 0, WARNING: 0, INFO: 0, SECURE: 0}
        # Base Config
        b_cfg = parsed.getElementsByTagName('base-config')
        # 0 or 1 of <base-config>
        if b_cfg:
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        '基本配置不安全地配置为允许到所有域的明文流量。'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            if b_cfg[0].getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        '基本配置配置为禁止到所有域的明文流量。'),
                    'severity': SECURE,
                })
                summary[SECURE] += 1
            trst_anch = b_cfg[0].getElementsByTagName('trust-anchors')
            if trst_anch:
                certs = trst_anch[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置配置为信任'
                                f'捆绑证书 {loc}。'),
                            'severity': INFO,
                        })
                        summary[INFO] += 1
                    elif loc == 'system':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置配置为'
                                '信任系统证书。'),
                            'severity': WARNING,
                        })
                        summary[WARNING] += 1
                    elif loc == 'user':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置配置为'
                                '信任用户安装的证书。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '基本配置配置为'
                                '绕过证书固定。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
        # Domain Config
        dom_cfg = parsed.getElementsByTagName('domain-config')
        # Any number of <domain-config>
        for cfg in dom_cfg:
            domain_list = []
            domains = cfg.getElementsByTagName('domain')
            for dom in domains:
                domain_list.append(dom.firstChild.nodeValue)
            if cfg.getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        '域配置不安全地配置为'
                        '允许明文流量到达'
                        '范围内的这些域。'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            elif cfg.getAttribute('cleartextTrafficPermitted') == 'false':
                finds.append({
                    'scope': domain_list,
                    'description': (
                        '域配置已安全配置为'
                        '禁止明文流量流向'
                        '范围内的这些域。'),
                    'severity': SECURE,
                })
                summary[SECURE] += 1
            dtrust = cfg.getElementsByTagName('trust-anchors')
            if dtrust:
                certs = dtrust[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域配置配置为信任'
                                f'捆绑证书 {loc}。'),
                            'severity': INFO,
                        })
                        summary[INFO] += 1
                    elif loc == 'system':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域配置配置为'
                                '信任系统证书。'),
                            'severity': WARNING,
                        })
                        summary[WARNING] += 1
                    elif loc == 'user':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域配置配置为'
                                '信任用户安装的证书。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': domain_list,
                            'description': (
                                '域配置配置为'
                                '绕过证书固定。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
            pinsets = cfg.getElementsByTagName('pin-set')
            if pinsets:
                exp = pinsets[0].getAttribute('expiration')
                pins = pinsets[0].getElementsByTagName('pin')
                all_pins = []
                for pin in pins:
                    digest = pin.getAttribute('digest')
                    pin_val = pin.firstChild.nodeValue
                    if digest:
                        tmp = f'Pin: {pin_val} Digest: {digest}'
                    else:
                        tmp = f'Pin: {pin_val}'
                    all_pins.append(tmp)
                pins_list = ','.join(all_pins)
                if exp:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            '证书固定到期日期 '
                            f' {exp}。在此日期之后，固定将被禁用。'
                            f'[{pins_list}]'),
                        'severity': INFO,
                    })
                    summary[INFO] += 1
                else:
                    finds.append({
                        'scope': domain_list,
                        'description': (
                            '证书固定没有有效期。'
                            '确保在证书过期之前更新。 '
                            f'[{pins_list}]'),
                        'severity': SECURE,
                    })
                    summary[SECURE] += 1
        # Debug Overrides
        de_over = parsed.getElementsByTagName('debug-overrides')
        # 0 or 1 of <debug-overrides>
        if de_over and is_debuggable:
            if de_over[0].getAttribute('cleartextTrafficPermitted') == 'true':
                finds.append({
                    'scope': ['*'],
                    'description': (
                        '调试覆盖配置为允许到所有域的明文流量，'
                        '并且应用程序是可调试的。'),
                    'severity': HIGH,
                })
                summary[HIGH] += 1
            otrst_anch = de_over[0].getElementsByTagName('trust-anchors')
            if otrst_anch:
                certs = otrst_anch[0].getElementsByTagName('certificates')
                for cert in certs:
                    loc = cert.getAttribute('src')
                    override = cert.getAttribute('overridePins')
                    if '@raw/' in loc:
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '调试覆盖配置为信任'
                                f'捆绑的调试证书 {loc}。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
                    if override == 'true':
                        finds.append({
                            'scope': ['*'],
                            'description': (
                                '调试覆盖配置为'
                                '绕过证书固定。'),
                            'severity': HIGH,
                        })
                        summary[HIGH] += 1
        netsec['network_findings'] = finds
        netsec['network_summary'] = summary
    except Exception:
        logger.exception('Performing Network Security Analysis')
    return netsec
