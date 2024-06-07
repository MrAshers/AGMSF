# AGMSF

![](mobsf/static/img/mobsf_Readme.png)

👋`AndroMSF` 是 **南京审计大学** 2020 级计算机学院 **周梓豪** 做的毕业设计，是一个基于`Androguard` 的 `Android` 应用安全分析系统。`AndroMSF`  使用 `Django` 框架开发，使用 `SQLite` 进行存储。

Made ![Love](https://cloud.githubusercontent.com/assets/4301109/16754758/82e3a63c-4813-11e6-9430-6015d98aeaab.png) in China.

[![python](https://img.shields.io/badge/python-3.10+-blue.svg?logo=python&labelColor=yellow)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/mobsf.svg)](https://badge.fury.io/py/mobsf)
[![platform](https://img.shields.io/badge/platform-windows-green.svg)](https://github.com/MobSF/Mobile-Security-Framework-MobSF/)
[![License](https://img.shields.io/:license-GPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)

## 📚安装环境依赖

- [Python 3.10+](https://www.python.org/)
- [Git](https://git-scm.com/download/win)
- [JDK 8+](https://www3.ntu.edu.sg/home/ehchua/programming/howto/JDK_Howto.html)
- [Microsoft Visual C++ Build Tools](https://visualstudio.microsoft.com/zh-hans/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16)
- [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)
- [wkhtmltopdf](https://wkhtmltopdf.org/downloads.html)

## 👆安装完成后

```bash
git clone https://github.com/MrAshers/AGMSF.git
cd AGMSF
setup.bat
```
## 🌱运行！

```bash
run.bat 127.0.0.1:8000
```
在浏览器中打开 `http://localhost:8000/` 即可访问!

## 📝使用说明

- 选择自己想分析的 **Android APK** 文件拖入上传框或选择文件，上传成功即自动开始分析
- 分析完成后即可查看分析结果，可导出为 **PDF** 文件
- 结果对每个 APK 都有评分，评分越高越安全，评分依据 **CVSS评分系统** 判定

## Static Analysis
### 首页

![](mobsf/static/img/4examples/home.png)

### 分析记录
![](mobsf/static/img/4examples/recent.png)

### 分析报告
![](mobsf/static/img/4examples/report.png)

### 导出 PDF 报告

![](mobsf/static/img/4examples/pdf.png)

### 分数卡
![](mobsf/static/img/4examples/appsec.png)