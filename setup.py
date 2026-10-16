"""py2app 打包配置: python3.13 setup.py py2app"""
from setuptools import setup

APP = ["openconnect_gui.py"]
TCLTK = "/opt/homebrew/opt/tcl-tk/lib"
OPTIONS = {
    "argv_emulation": False,
    "plist": {
        "CFBundleName": "OpenConnect GUI",
        "CFBundleDisplayName": "OpenConnect GUI",
        "CFBundleIdentifier": "com.novo.openconnect-gui",
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0.0",
        "LSMinimumSystemVersion": "12.0",
        "NSHighResolutionCapable": True,
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    },
}

setup(
    app=APP,
    name="OpenConnect GUI",
    options={"py2app": OPTIONS},
)
