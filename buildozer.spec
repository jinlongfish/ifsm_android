[app]
title = InfinityFree Site Manager
package.name = ifsm
package.domain = org.example
source.dir = .
source.include_exts = py,kv,png,jpg,jpeg,svg,json,css,html,txt
version = 0.1.0
requirements = python3,kivy,openssl,certifi
orientation = landscape
fullscreen = 0
android.permissions = WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE,INTERNET,ACCESS_NETWORK_STATE
android.api = 34
android.minapi = 23
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = True
android.keep_activity = True
[buildozer]
log_level = 2
warn_on_root = 1
[python]
