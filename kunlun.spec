"""
KunLun Penetration Testing Platform - PyInstaller Spec File

Usage: pyinstaller kunlun.spec --clean
"""

import sys
import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.absolute()

# 是否为加密后的构建
ENCRYPTED_BUILD = os.environ.get('ENCRYPTED_BUILD', '0') == '1'
BUILD_DIR = PROJECT_ROOT / 'dist_encrypted' if ENCRYPTED_BUILD else PROJECT_ROOT

# 收集所有隐藏导入
hiddenimports = []

# 递归收集关键库的导入
libs_to_collect = [
    'aioquic', 'PyQt6', 'sklearn', 'scapy', 'dnslib', 'jwt',
    'aiosqlite', 'aiohttp', 'asyncio', 'cryptography',
    'requests', 'urllib3', 'certifi', 'chardet', 'idna',
    'numpy', 'pandas', 'scipy', 'joblib', 'threadpoolctl',
    'nuclei', 'mitmproxy', 'colorama', 'click', 'tqdm',
    'websockets', 'pyyaml', 'toml', 'jinja2', 'markupsafe',
    'sqlalchemy', 'alembic', 'mako', 'python-dateutil',
    'six', 'attrs', 'cattrs', 'pydantic', 'orjson',
    'h11', 'h2', 'hpack', 'hyperframe', 'priority',
    'sortedcontainers', 'cachetools', 'itsdangerous',
    'multidict', 'yarl', 'frozenlist', 'async-timeout',
    'cffi', 'pycparser', 'bcrypt', 'argon2-cffi',
    'websocket-client', 'websockets', 'psutil', 'netifaces',
    'pcapy', 'dpkt', 'scapy_http', 'ipaddress',
    'impacket', 'ldap3', 'pyasn1', 'asn1crypto',
    'paramiko', 'pynacl', 'bcrypt', 'ecdsa',
    'qdarkstyle', 'qtpy', 'sip', 'pyqtgraph',
    'matplotlib', 'seaborn', 'plotly', 'dash',
    'networkx', 'imageio', 'pillow', 'opencv-python',
    'nltk', 'transformers', 'torch', 'tensorflow',
    'scikit-image', 'scikit-learn', 'xgboost', 'lightgbm',
    'gensim', 'spacy', 'textblob', 'langdetect',
]

for lib in libs_to_collect:
    try:
        collected = collect_all(lib)
        hiddenimports.extend(collected[0])  # 隐藏导入
    except Exception:
        pass

# 添加其他必要的隐藏导入
hiddenimports.extend([
    'sklearn.utils._cython_blas',
    'sklearn.neighbors._typedefs',
    'sklearn.neighbors._quad_tree',
    'sklearn.tree._utils',
    'sklearn.utils._weight_vector',
    'sklearn.neighbors._kd_tree',
    'sklearn.neighbors._distance',
    'sklearn.cluster._dbscan_inner',
    'sklearn.cluster._hierarchical_fclust',
    'sklearn.cluster._ward_tree',
    'sklearn.linear_model._cd_fast',
    'sklearn.linear_model._sgd_fast',
    'sklearn.linear_model._lsqr',
    'sklearn.svm._libsvm',
    'sklearn.svm._liblinear',
    'sklearn.decomposition._nmf',
    'sklearn.metrics._pairwise_distances_reduction',
    'sklearn.metrics._pairwise_fast',
    'sklearn.feature_extraction._hashing',
    'sklearn.preprocessing._discretization',
    'sklearn.preprocessing._data',
    'scipy._lib.messagestream',
    'scipy.special._ufuncs_cxx',
    'scipy.linalg.cython_blas',
    'scipy.linalg.cython_lapack',
    'scipy.sparse._sparsetools',
    'scipy.sparse.linalg._dsolve',
    'scipy.sparse.linalg._iterative',
    'scipy.sparse.linalg._eigen.arpack',
    'scipy.sparse.linalg._eigen.lobpcg',
    'scipy.spatial._ckdtree',
    'scipy.spatial._qhull',
    'scipy.spatial._distance_wrap',
    'scipy.ndimage._nd_image',
    'scipy.interpolate._fitpack',
    'scipy.interpolate._bspl',
    'scipy.interpolate._cubic',
    'scipy.integrate._quadpack',
    'scipy.integrate._odepack',
    'scipy.integrate._lsoda',
    'scipy.integrate._dopri5',
    'scipy.optimize._lbfgsb',
    'scipy.optimize._cobyla',
    'scipy.optimize._slsqp',
    'scipy.optimize._trlib',
    'scipy.optimize._linprog',
    'scipy.optimize._minimize',
    'scipy.signal._signaltools',
    'scipy.signal._spectral',
    'scipy.signal._fir_filter_design',
    'scipy.signal._peak_finding',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'PyQt6.QtWidgets',
    'PyQt6.QtNetwork',
    'PyQt6.QtSvg',
    'PyQt6.QtPrintSupport',
    'PyQt6.QtWebEngineWidgets',
    'PyQt6.QtWebChannel',
    'PyQt6.QtQuick',
    'PyQt6.QtQuickWidgets',
    'aioquic.asyncio',
    'aioquic.h3',
    'aioquic.quic',
    'aioquic.tls',
    'mitmproxy.addons',
    'mitmproxy.certs',
    'mitmproxy.connection',
    'mitmproxy.flow',
    'mitmproxy.http',
    'mitmproxy.net',
    'mitmproxy.proxy',
    'mitmproxy.tools',
    'nuclei.engine',
    'nuclei.types',
    'nuclei.output',
    'nuclei.protocols',
    'impacket.smb',
    'impacket.dcerpc',
    'impacket.krb5',
    'impacket.win32',
    'libnmap.process',
    'libnmap.parser',
    'libnmap.diff',
    'libnmap.report',
])

# 数据文件列表
datas = []

# 添加项目数据目录
data_dirs = [
    ('rules', 'rules'),
    ('profiles', 'profiles'),
    ('templates', 'templates'),
    ('certs', 'certs'),
    ('plugins', 'plugins'),
    ('assets', 'assets'),
    ('config', 'config'),
    ('locales', 'locales'),
    ('core/modules/gadget_chains', 'core/modules/gadget_chains'),
]

for src, dst in data_dirs:
    src_path = BUILD_DIR / src
    if src_path.exists():
        datas.append((str(src_path), dst))

# 添加根目录配置文件
root_files = ['config/app.yaml', 'README.md']
for f in root_files:
    f_path = BUILD_DIR / f
    if f_path.exists():
        datas.append((str(f_path), '.'))

# 二进制文件
binaries = []

# 平台特定配置
if sys.platform == 'win32':
    # Windows 特定配置
    icon_file = str(BUILD_DIR / 'assets' / 'icon.ico') if (BUILD_DIR / 'assets' / 'icon.ico').exists() else None
    console = False  # 无控制台模式
    uac_admin = True  # 请求管理员权限
    
elif sys.platform == 'darwin':
    # macOS 特定配置
    icon_file = str(BUILD_DIR / 'assets' / 'icon.icns') if (BUILD_DIR / 'assets' / 'icon.icns').exists() else None
    console = False
    uac_admin = False
    
else:
    # Linux 特定配置
    icon_file = None
    console = False
    uac_admin = False

# 主入口脚本
main_script = str(BUILD_DIR / 'main.py')

a = Analysis(
    [main_script],
    pathex=[str(BUILD_DIR)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'PyQt5', 'wx', 'gtk',
        'PIL', 'imageio', 'scikit-image',
        'torch', 'tensorflow', 'transformers',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='kunlun',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 使用 UPX 压缩
    upx_exclude=[],
    runtime_tmpdir=None,
    console=console,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
    uac_admin=uac_admin,  # Windows UAC 管理员权限
)

# macOS 应用包
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='KunLun.app',
        icon=icon_file,
        bundle_identifier='com.kunlun.pentest',
    )
