# -*- coding: utf_8 -*-
"""Module holding the functions for cert analysis."""

import hashlib
import logging
import os
import re
import subprocess
from pathlib import Path

import asn1crypto

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    rsa,
)

from django.utils.html import escape

from mobsf.MobSF.utils import (
    find_java_binary,
    gen_sha256_hash,
)
from mobsf.StaticAnalyzer.tools.androguard4.apk import (
    get_certificate_name_string,
)

logger = logging.getLogger(__name__)
ANDROID_8_1_LEVEL = 27
HIGH = 'high'
WARNING = 'warning'
INFO = 'info'
HASH_FUNCS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
}


def get_hardcoded_cert_keystore(files):
    """Returns the hardcoded certificate keystore."""
    try:
        logger.info('Getting Hardcoded Certificates/Keystores')
        findings = []
        certz = []
        key_store = []
        for file_name in files:
            if '.' not in file_name:
                continue
            ext = Path(file_name).suffix
            if ext in ('.cer', '.pem', '.cert', '.crt',
                       '.pub', '.key', '.pfx', '.p12', '.der'):
                certz.append(escape(file_name))
            if ext in ('.jks', '.bks'):
                key_store.append(escape(file_name))
        if certz:
            desc = 'Certificate/Key files hardcoded inside the app.'
            findings.append({'finding': desc, 'files': certz})
        if key_store:
            desc = 'Hardcoded Keystore found.'
            findings.append({'finding': desc, 'files': key_store})
        return findings
    except Exception:
        logger.exception('Getting Hardcoded Certificates/Keystores')


def get_cert_details(data):
    """Get certificate details."""
    certlist = []
    x509_cert = asn1crypto.x509.Certificate.load(data)
    subject = get_certificate_name_string(x509_cert.subject, short=True)
    certlist.append(f'X.509 主题: {subject}')
    certlist.append(f'签名算法: {x509_cert.signature_algo}')
    valid_from = x509_cert['tbs_certificate']['validity']['not_before'].native
    certlist.append(f'有效期开始时间: {valid_from}')
    valid_to = x509_cert['tbs_certificate']['validity']['not_after'].native
    certlist.append(f'有效期到期时间: {valid_to}')
    issuer = get_certificate_name_string(x509_cert.issuer, short=True)
    certlist.append(f'颁发者信息: {issuer}')
    certlist.append(f'证书序列号: {hex(x509_cert.serial_number)}')
    certlist.append(f'Hash 算法: {x509_cert.hash_algo}')
    for k, v in HASH_FUNCS.items():
        certlist.append(f'{k}: {v(data).hexdigest()}')
    return certlist


def get_pub_key_details(data):
    """Get public key details."""
    certlist = []

    x509_public_key = serialization.load_der_public_key(
        data,
        backend=default_backend())
    alg = 'unknown'
    fingerprint = ''
    if isinstance(x509_public_key, rsa.RSAPublicKey):
        alg = 'rsa'
        modulus = x509_public_key.public_numbers().n
        public_exponent = x509_public_key.public_numbers().e
        to_hash = f'{modulus}:{public_exponent}'
    elif isinstance(x509_public_key, dsa.DSAPublicKey):
        alg = 'dsa'
        dsa_parameters = x509_public_key.parameters()
        p = dsa_parameters.parameter_numbers().p
        q = dsa_parameters.parameter_numbers().q
        g = dsa_parameters.parameter_numbers().g
        y = x509_public_key.public_numbers().y
        to_hash = f'{p}:{q}:{g}:{y}'
    elif isinstance(x509_public_key, ec.EllipticCurvePublicKey):
        alg = 'ec'
        to_hash = f'{x509_public_key.public_numbers().curve.name}:'
        to_hash = to_hash.encode('utf-8')
        # Untested, possibly wrong key size and fingerprint
        to_hash += data[25:]
    fingerprint = gen_sha256_hash(to_hash)
    certlist.append(f'公钥算法: {alg}')
    certlist.append(f'证书位大小: {x509_public_key.key_size}')
    certlist.append(f'证书指纹: {fingerprint}')
    return certlist


def get_signature_versions(app_path, tools_dir, signed):
    """Get signature versions using apksigner."""
    v1, v2, v3, v4 = False, False, False, False
    try:
        if not signed:
            return v1, v2, v3, v4
        logger.info('Getting Signature Versions')
        apksigner = Path(tools_dir) / 'apksigner.jar'
        args = [find_java_binary(), '-Xmx1024M',
                '-Djava.library.path=', '-jar',
                apksigner.as_posix(),
                'verify', '--verbose', app_path]
        out = subprocess.check_output(
            args, stderr=subprocess.STDOUT)
        out = out.decode('utf-8', 'ignore')
        if re.findall(r'v1 scheme \(JAR signing\): true', out):
            v1 = True
        if re.findall(r'\(APK Signature Scheme v2\): true', out):
            v2 = True
        if re.findall(r'\(APK Signature Scheme v3\): true', out):
            v3 = True
        if re.findall(r'\(APK Signature Scheme v4\): true', out):
            v4 = True
    except Exception:
        logger.exception('Failed to get signature versions')
    return v1, v2, v3, v4


def apksigtool_cert(apk_path, tools_dir):
    """Get Human readable certificate with apksigtool."""
    certlist = []
    certs = []
    pub_keys = []
    signed = False
    certs_no = 0
    min_sdk = None
    try:
        from apksigtool import (
            APKSignatureSchemeBlock,
            extract_v2_sig,
            parse_apk_signing_block,
        )
        _, sig_block = extract_v2_sig(apk_path)
        for pair in parse_apk_signing_block(sig_block).pairs:
            b = pair.value
            if isinstance(b, APKSignatureSchemeBlock):
                signed = True
                for signer in b.signers:
                    if b.is_v3():
                        min_sdk = signer.min_sdk
                    certs_no = len(signer.signed_data.certificates)
                    for cert in signer.signed_data.certificates:
                        d = get_cert_details(cert.data)
                        for i in d:
                            if i not in certs:
                                certs.append(i)
                    p = get_pub_key_details(signer.public_key.data)
                    for j in p:
                        if j not in pub_keys:
                            pub_keys.append(j)

        if signed:
            certlist.append('二进制文件已被签名')
        else:
            certlist.append('二进制文件未被签名')
        v1, v2, v3, v4 = get_signature_versions(apk_path, tools_dir, signed)
        certlist.append(f'v1 签名: {v1}')
        certlist.append(f'v2 签名: {v2}')
        certlist.append(f'v3 签名: {v3}')
        certlist.append(f'v4 签名: {v4}')
        certlist.extend(certs)
        certlist.extend(pub_keys)
        certlist.append(f'找到 {certs_no} 个证书')
    except Exception:
        logger.exception('Failed to parse code signing certificate')
        certlist.append('证书缺失')
    return {
        'cert_data': '\n'.join(certlist),
        'signed': signed,
        'v1': v1,
        'v2': v2,
        'v3': v3,
        'v4': v4,
        'min_sdk': min_sdk,
    }


def get_cert_data(a, app_path, tools_dir):
    """Get Human readable certificate."""
    certlist = []
    signed = False
    if a.is_signed():
        signed = True
        certlist.append('二进制文件已被签名')
    else:
        certlist.append('二进制文件未被签名')
        certlist.append('证书缺失')
    v1, v2, v3, v4 = get_signature_versions(app_path, tools_dir, signed)
    certlist.append(f'v1 签名: {v1}')
    certlist.append(f'v2 签名: {v2}')
    certlist.append(f'v3 签名: {v3}')
    certlist.append(f'v4 签名: {v4}')

    certs = set(a.get_certificates_der_v3() + a.get_certificates_der_v2()
                + [a.get_certificate_der(x)
                    for x in a.get_signature_names()])
    pkeys = set(a.get_public_keys_der_v3() + a.get_public_keys_der_v2())

    for cert in certs:
        certlist.extend(get_cert_details(cert))

    for public_key in pkeys:
        certlist.extend(get_pub_key_details(public_key))

    if len(certs) > 0:
        certlist.append(f'找到 {len(certs)} 个证书')

    return {
        'cert_data': '\n'.join(certlist),
        'signed': signed,
        'v1': v1,
        'v2': v2,
        'v3': v3,
        'v4': v4,
        'min_sdk': None,
    }


def cert_info(a, app_dic, man_dict):
    """Return certificate information."""
    try:
        logger.info('Reading Code Signing Certificate')
        manifestfile = None
        manidat = ''
        files = []
        summary = {HIGH: 0, WARNING: 0, INFO: 0}

        if a:
            cert_data = get_cert_data(
                a, app_dic['app_path'], app_dic['tools_dir'])
        else:
            logger.warning('androguard certificate parsing failed,'
                           ' switching to apksigtool')
            cert_data = apksigtool_cert(
                app_dic['app_path'], app_dic['tools_dir'])

        cert_path = os.path.join(app_dic['app_dir'], 'META-INF/')
        if os.path.exists(cert_path):
            files = [f for f in os.listdir(
                cert_path) if os.path.isfile(os.path.join(cert_path, f))]
        if 'MANIFEST.MF' in files:
            manifestfile = os.path.join(cert_path, 'MANIFEST.MF')
        if manifestfile:
            with open(manifestfile, 'r', encoding='utf-8') as manifile:
                manidat = manifile.read()
        sha256_digest = bool(re.findall(r'SHA-256-Digest', manidat))
        findings = []
        if cert_data['signed']:
            summary[INFO] += 1
            findings.append((
                INFO,
                '此应用程序使用代码签名证书进行签名',
                '已签名的证书'))
        else:
            summary[HIGH] += 1
            findings.append((
                HIGH,
                '找不到代码签名证书',
                '缺少代码签名证书'))

        if man_dict['min_sdk']:
            api_level = int(man_dict['min_sdk'])
        elif cert_data['min_sdk']:
            api_level = int(cert_data['min_sdk'])
        else:
            # API Level unknown
            api_level = None

        if cert_data['v1'] and api_level:
            status = HIGH
            summary[HIGH] += 1
            if ((cert_data['v2'] or cert_data['v3'])
                    and api_level < ANDROID_8_1_LEVEL):
                status = WARNING
                summary[HIGH] -= 1
                summary[WARNING] += 1
            findings.append((
                status,
                '此应用程序使用 v1 签名方案签名，'
                '如果仅使用 v1 签名方案，'
                '则容易受到 Android 5.0-8.0 上的 Janus 漏洞攻击。'
                '在使用 v1 和 v2/v3 方案签名的 Android 5.0-7.0 '
                '上运行的应用程序也容易受到攻击。',
                '此应用程序容易受到 Janus 漏洞的影响'))
        if re.findall(r'CN=Android Debug', cert_data['cert_data']):
            summary[HIGH] += 1
            findings.append((
                HIGH,
                '此应用程序使用调试证书签名。'
                '已发行的应用程序不得使用调试证书。',
                '此应用程序使用调试证书签名'))
        if re.findall(r'Hash Algorithm: sha1', cert_data['cert_data']):
            status = HIGH
            summary[HIGH] += 1
            desc = (
                '此应用程序使用 SHA1withRSA 签名。 '
                'SHA1 哈希算法已知存在冲突问题。')
            title = '证书算法易受哈希冲突影响'
            if sha256_digest:
                status = WARNING
                summary[HIGH] -= 1
                summary[WARNING] += 1
                desc += (
                    ' 此 manifest 文件使用 SHA256withRSA 。')
                title = ('证书算法可能容易受到哈希冲突的影响')
            findings.append((status, desc, title))
        if re.findall(r'Hash Algorithm: md5', cert_data['cert_data']):
            status = HIGH
            summary[HIGH] += 1
            desc = (
                '此应用程序使用 MD5 签名。'
                'MD5 哈希算法已知存在冲突问题。')
            title = '证书算法可能容易受到哈希冲突的影响'
            findings.append((status, desc, title))
        return {
            'certificate_info': cert_data['cert_data'],
            'certificate_findings': findings,
            'certificate_summary': summary,
        }
    except Exception:
        logger.exception('Reading Code Signing Certificate')
        return {}
