MANIFEST_DESC = {
    'well_known_assetlinks': {
        'title': ('未找到 App Link assetlinks.json 文件'
                  '<br>[android:name=%s]<br>[android:host=%s]'),
        'level': 'high',
        'description': ('未找到 App Link 资产验证网址 (%s) 或配置不正确。(状态代码: %s)'
                        'App Links 允许用户从Web URL或电子邮件重定向到移动应用程序。'
                        '如果此文件丢失或未正确配置为 App Link 主机/域，'
                        '则恶意应用可能会劫持此类 URL。'
                        '这可能会导致网络钓鱼攻击、泄露 URI 中的敏感数据，例如'
                        'PII、OAuth 令牌、魔术链接/密码重置令牌等。'
                        '您必须通过托管 assetlinks.json 文件'
                        '并通过 Activity intent-filter 中的'
                        ' [android：autoVerify=“true”] 启用验证来验证 App Link 域。'),
        'name': ('App Link assetlinks.json file not found '
                 '[android:name=%s], [android:host=%s]'),
    },
    'clear_text_traffic': {
        'title': ('此 APP 启用明文流量'
                  '<br>[android:usesCleartextTraffic=true]'),
        'level': 'high',
        'description': ('此应用程序使用明文网络流量，例如明文HTTP、FTP栈、下载管理器和播放器。'
                        'API 级别 27 或更低级别的应用的默认值为“true”，'
                        'API 级别 28 或更高级别的应用默认为“false”。'
                        '避免明文流量的关键原因是缺乏机密性、真实性和防篡改保护;'
                        '网络攻击者可以窃听传输的数据，也可以在不被发现的情况下对其进行修改。'),
        'name': ('Clear text traffic is Enabled For App '
                 '[android:usesCleartextTraffic=true]'),
    },
    'direct_boot_aware': {
        'title': '此应用程序有直接启动模式 <br>[android:directBootAware=true]',
        'level': 'info',
        'description': ('此应用程序可以在用户解锁设备之前运行。'
                        '如果您使用的是应用程序的自定义子类，并且应用程序中的任何组件是直接启动的，'
                        '则整个自定义应用程序都被视为直接启动。'
                        '在直接启动期间，你的应用程序只能访问存储在受设备保护的数据'),
        'name': 'App is direct-boot aware [android:directBootAware=true]',
    },
    'has_network_security': {
        'title': ('此应用程序具有网络安全配置'
                  '<br>[android:networkSecurityConfig=%s]'),
        'level': 'info',
        'description': ('网络安全配置功能允许应用在安全的声明性配置文件中自定义其网络安全设置，'
                        '而无需修改应用代码。'
                        '可以为特定域和特定应用配置这些设置。'),
        'name': ('App has a Network Security Configuration '
                 '[android:networkSecurityConfig=%s]'),
    },
    'vulnerable_os_version': {
        'title': ('此应用程序可被安装在易受攻击的修补 Android 版本'
                  '<br>Android %s, [minSdk=%s]上'),
        'level': 'high',
        'description': ('此应用程序可以安装在具有多个未修复漏洞的旧版本的 android 上。'
                        '这些设备不会收到来自 Google 的安全更新。'
                        '支持 Android 版本 => 10, API 29 接收合理的安全更新。'),
        'name': ('App can be installed on a vulnerable '
                 'upatched Android version %s, [minSdk=%s]'),
    },
    'vulnerable_os_version2': {
        'title': ('此应用程序可以安装在易受攻击的 Android 版本'
                  '<br>Android %s, minSdk=%s]上'),
        'level': 'warning',
        'description': ('此应用程序可以安装在具有多个漏洞的旧版本的 android 上。'
                        '支持 Android 版本 => 10, API 29 接收合理的安全更新。'),
        'name': ('App can be installed on a vulnerable Android version'
                 ' %s, [minSdk=%s]'),
    },
    'app_is_debuggable': {
        'title': '此 APP 启用调式类<br>[android:debuggable=true]',
        'level': 'high',
        'description': ('在应用程序上启用了调试，'
                        '这使得逆向工程师更容易将调试器挂接到它。'
                        '这允许转储堆栈跟踪并访问调试帮助程序类。'),
        'name': 'Debug Enabled For App [android:debuggable=true]',
    },
    'app_allowbackup': {
        'title': ('此应用程序的数据可被备份'
                  '<br>[android:allowBackup=true]'),
        'level': 'warning',
        'description': ('此标志允许任何人通过 adb 备份您的应用程序数据。'
                        '它允许启用 USB 调试的用户从设备中复制应用程序数据。'),
        'name': 'Application Data can be Backed up [android:allowBackup=true]',
    },
    'allowbackup_not_set': {
        'title': ('此应用程序的数据可被备份<br>[android:allowBackup]'
                  ' 标志缺失'),
        'level': 'warning',
        'description': ('标志 [android:allowBackup] 应被设置为false。'
                        '默认情况下，它设置为 true，'
                        '并允许任何人通过 adb 备份您的应用程序数据。'
                        '它允许启用 USB 调试的用户从设备中复制应用程序数据。'),
        'name': ('Application Data can be Backed up [android:allowBackup] flag'
                 ' is missing.'),
    },
    'app_in_test_mode': {
        'title': '此应用程序处于测试模式 <br>[android:testOnly=true]',
        'level': 'high',
        'description': ('它可能会暴露自身之外的功能或数据，'
                        '从而导致安全漏洞。'),
        'name': 'Application is in Test Mode [android:testOnly=true]',
    },
    'task_affinity_set': {
        'title': '为活动 <br>(%s) 设置了 TaskAffinity',
        'level': 'warning',
        'description': ('如果设置了 taskAffinity，'
                        '则其他应用程序可以读取发送到属于另一个任务的活动的 Intent。'
                        '始终使用默认设置，将相关性保留为包名称，'
                        '以防止发送或接收的 Intent 中的敏感信息被其他应用程序读取。'),
        'name': 'TaskAffinity is set for Activity (%s)',
    },
    'non_standard_launchmode': {
        'title': '活动启动模式 (%s) 不是标准的',
        'level': 'warning',
        'description': ('Activity 不应将启动模式属性设置为"singleTask/singleInstance"，'
                        '因为它成为 root Activity，并且其他应用程序可以读取调用 Intent 的内容。'
                        '因此，当 Intent 中包含敏感信息时，需要使用"standard"启动模式属性。'),
        'name': 'Launch Mode of activity (%s) is not standard.',
    },
    'task_hijacking': {
        'title': ('Activity (%s) 容易受到 Android 任务劫持/StrandHogg 的攻击'),
        'level': 'high',
        'description': ('活动不应将启动模式属性设置为"singleTask"。'
                        '其他应用程序可能会在活动堆栈顶部放置恶意活动，'
                        '从而导致任务劫持/StrandHogg 1.0 漏洞。'
                        '这使得该应用程序很容易成为网络钓鱼攻击的目标。'
                        '可以通过将启动模式属性设置为"singleInstance"或'
                        '设置空的 taskAffinity (taskAffinity="") 属性来修复该漏洞。'
                        '您还可以将应用程序的目标 SDK 版本 (%s) 更新到 28 或更高版本，以在平台级别修复此问题。'),
        'name': ('Activity (%s) is vulnerable to Android '
                 'Task Hijacking/StrandHogg.'),
    },
    'task_hijacking2': {
        'title': '活动 (%s) 容易受到 StrandHogg 2.0 的攻击',
        'level': 'high',
        'description': ('Activity 被发现易受StrandHogg 2.0任务劫持漏洞的影响。'
                        '当易受攻击时，其他应用程序可能会在易受攻击的应用程序的活动堆栈上放置恶意活动。'
                        '这使得该应用程序很容易成为网络钓鱼攻击的目标。'
                        '可以通过将启动模式属性设置为"singleInstance"'
                        '并设置空的taskAffinity (taskAffinity="") 来修复该漏洞。'
                        '您还可以将应用程序的目标 SDK 版本 (%s) 更新到 29 或更高版本，以在平台级别修复此问题。'),
        'name': 'Activity (%s) is vulnerable to StrandHogg 2.0',
    },
    'improper_provider_permission': {
        'title': 'Content Provider 权限不当 <br>[%s]',
        'level': 'warning',
        'description': ('Content Provider权限设置为允许从设备上的任何其他应用程序进行访问。'
                        'Content Provider可能包含有关应用程序的敏感信息，因此不应共享。'),
        'name': 'Improper Content Provider Permissions',
    },
    'dialer_code_found': {
        'title': ('发现拨号器代码: %s '
                  ' <br>[android:scheme="android_secret_code"]'),
        'level': 'warning',
        'description': ('在manifest中发现了秘密代码。'
                        '当这些代码输入拨号器时，'
                        '将授予对可能包含敏感信息的隐藏内容的访问权限。'),
        'name': ('Dailer Code: %s Found.'
                 ' [android:scheme="android_secret_code"]'),
    },
    'sms_receiver_port_found': {
        'title': '找到设置在端口的数据 SMS 接收器: %s <br>[android:port]',
        'level': 'warning',
        'description': ('二进制 SMS 接收器被配置为监听端口。'
                        '发送到设备的二进制 SMS 消息由应用程序以开发人员选择的方式进行处理。'
                        '应用程序应正确验证此 SMS 中的数据。'
                        '此外，应用程序应假设收到的 SMS 来自不受信任的来源'),
        'name': 'Data SMS Receiver Set on Port: %s Found. [android:port]',
    },
    'high_intent_priority_found': {
        'title': '高 Intent 优先级 (%s)<br>[android:priority]',
        'level': 'warning',
        'description': ('通过将 Intent 优先级设置为高于其他 Intent，'
                        '应用程序可以有效地覆盖其他请求。'),
        'name': 'High Intent Priority (%s). [android:priority]',
    },
    'high_action_priority_found': {
        'title': '高 Action 优先级 (%s)<br>[android:priority] ',
        'level': 'warning',
        'description': ('通过将 Action 优先级设置为高于其他 Action，'
                        '应用程序可以有效地覆盖其他请求'),
        'name': 'High Action Priority (%s). [android:priority]',
    },
    'exported_protected_permission_signature': {
        'title': ('<strong>%s</strong> (%s) 受权限保护'
                  '<br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('%s %s 被发现导出，但受权限保护。'),
        'name': ('%s %s is Protected by a permission.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_normal': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受权限保护。但权限的保护级别设置为 normal。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_dangerous': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受权限保护。但权限的保护级别设置为 danger!'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_signatureorsystem': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现 %s %s 已导出，但受到权限保护。'
                        '但是，权限的保护级别设置为 signatureOrSystem。'
                        '建议使用签名级别。'
                        '签名级别应该满足大多数用途，并且不依赖于应用程序在设备上的安装位置。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_not_defined': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '受分析的应用程序中被未定义的权限保护。'
                        '因此，应在定义权限的地方检查权限的保护级别。'
                        '如果设置为normal或danger，'
                        '恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用同一证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level '
                 'of the permission should be '
                 'checked. [%s] [android:exported=true]'),
    },
    'exported_protected_permission_normal_app_level': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受应用程序级别的权限保护。'
                        '但权限的保护级别设置为normal。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be '
                 'checked. [%s] [android:exported=true]'),
    },
    'exported_protected_permission_dangerous_app_level': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受应用程序级别的权限保护。'
                        '但权限的保护级别设置为danger。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be '
                 'checked. [%s] [android:exported=true]'),
    },
    'exported_protected_permission': {
        'title': ('<strong>%s</strong> (%s)  受应用程序级别的权限保护'
                  '<br>%s<br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现 %s %s 已导出，'
                        '但受到应用程序级别权限的保护。'),
        'name': ('%s %s Protected by a permission at the application level.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_signatureorsystem_app_level': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'info',
        'description': ('发现 A%s %s 已导出，但受到应用程序级别权限的保护。'
                        '但是，权限的保护级别设置为signatureOrSystem。'
                        '建议使用签名级别。签名级别应该满足大多数用途，'
                        '并且不依赖于应用程序在设备上的安装位置。'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'exported_protected_permission_app_level': {
        'title': ('<strong>%s</strong> (%s) 受应用程序中的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受应用程序级别的权限保护，该权限未在分析的应用程序中定义。'
                        '因此，应在定义权限的地方检查权限的保护级别。'
                        '如果设置为normal或danger，恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用同一证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application, but the'
                 ' protection level of the permission should be checked.'
                 ' [%s] [android:exported=true]'),
    },
    'explicitly_exported': {
        'title': ('<strong>%s</strong> (%s) 未被保护.'
                  ' <br>[android:exported=true]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它'),
        'name': '%s %s is not Protected. [android:exported=true]',
    },
    'exported_intent_filter_exists': {
        'title': ('<strong>%s</strong> (%s) 未被保护。<br>'
                  '存在Intent过滤器'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        'Intent过滤器的存在表明 %s 已显式导出。'),
        'name': '%s %s is not Protected.An intent-filter exists.',
    },
    'exported_provider': {
        'title': ('<strong>%s</strong> (%s) 未被保护 <br>'
                  '[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它是一个针对 API 级别低于 17 的Content Provider，'
                        '无论应用程序运行的系统的 API 级别如何，它都会被默认导出'),
        'name': ('%s %s is not Protected.'
                 ' [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_2': {
        'title': (' 如果应用程序在 API 级别低于 17 的设备上运行，则<strong>%s</strong> (%s)不会受到保护。'
                  '<br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别低于 17 的设备上运行，则将导出Content Provider（%s %s）。'
                        '在这种情况下，它将与设备上的其他应用程序共享，'
                        '因此任何其他应用程序都可以访问它设备上的应用程序。'),
        'name': ('%s %s would not be Protected if'
                 ' the application ran on a device'
                 ' where the the API level was less than 17.'
                 ' [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_normal': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受权限保护。但权限的保护级别设置为normal。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level'
                 ' of the permission should be checked.'
                 ' [%s] [Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'exported_provider_danger': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受权限保护。但权限的保护级别设置为danger。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of '
                 'the permission should be checked. [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_signature': {
        'title': ('<strong>%s</strong> (%s) 受权限保护'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它'
                        '它受许可保护。'),
        'name': ('%s %s is Protected by a permission. [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_signatureorsystem': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现 %s %s 已导出，但受到权限保护。'
                        '但是，权限的保护级别设置为signatureOrSystem。'
                        '建议使用签名级别。'
                        '签名级别应该满足大多数用途，并且不依赖于应用程序在设备上的安装位置'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of '
                 'the permission should be checked. [%s] [Content Provider, '
                 'targetSdkVersion < 17]'),
    },
    'exported_provider_unknown': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受到分析的应用程序中未定义的权限的保护。'
                        '因此，保护级别应检查定义的权限。'
                        '如果设置为normal或danger，恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用同一证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked. [%s] [Content Provider,'
                 ' targetSdkVersion < 17]'),
    },
    'exported_provider_normal_app': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受应用程序级别的权限保护。'
                        '但权限的保护级别设置为normal。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_danger_appl': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受应用程序级别的权限保护。'
                        '但权限的保护级别设置为danger。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, but'
                 ' the protection level of the permission should be checked.'
                 '[%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_signature_appl': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受应用程序级别的权限保护。'),
        'name': ('%s %s is Protected by a permission at the application level.'
                 '[%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_signatureorsystem_app': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'info',
        'description': ('发现 %s %s 已导出，但受到应用程序级别的权限保护。'
                        '但是，权限的保护级别设置为signatureOrSystem。'
                        '建议使用签名级别。'
                        '签名级别应该满足大多数用途，并且不依赖于应用程序在设备上的安装位置'),
        'name': ('%s %s is Protected by a permission'
                 ' at the application level, '
                 'but the protection level of the permission should be '
                 'checked. [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_unknown_app': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion < 17]'),
        'level': 'warning',
        'description': ('发现 %s %s 与设备上的其他应用程序共享，'
                        '因此设备上的任何其他应用程序都可以访问它。'
                        '它受到分析的应用程序中未定义的权限的保护。'
                        '因此，保护级别应检查定义的权限。'
                        '如果设置为normal或danger，恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用同一证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission at application level, but'
                 ' the protection level of the permission should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion < 17]'),
    },
    'exported_provider_normal_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但如果应用程序运行在API级别小于17的设备上，则应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别低于 17 的设备上运行，'
                        '则Content Provider (%s) 将被导出。'
                        '在这种情况下，它仍将受到权限的保护。'
                        '但权限的保护级别设置为normal。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked if the application runs '
                 'on a device where the the API level is less than 17 '
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_danger_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但如果应用程序运行在API级别小于17的设备上，则应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别低于 17 的设备上运行，'
                        '则Content Provider (%s) 将被导出。'
                        '在这种情况下，它仍将受到权限的保护。'
                        '但权限的保护级别设置为danger。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission'
                 ', but the protection level of'
                 ' the permission should be checked if the application runs on'
                 ' a device where the the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signature_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用程序在 API 级别低于 17 的设备上运行，'
                        '则Content Provider (%s) 将被导出。不过，它受到权限的保护。'),
        'name': ('%s %s is Protected by a permission.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signatureorsystem_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，但应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用程序在 API 级别低于 17 的设备上运行，'
                        '则Content Provider (%s) 将被导出。'
                        '在这种情况下，它仍将受到权限的保护。'
                        '但是，权限的保护级别设置为signatureOrSystem。'
                        '建议使用签名级别。'
                        '签名级别应该足以满足大多数用途，并且不依赖于应用程序在设备上的安装位置'),
        'name': ('%s %s is Protected by a permission,'
                 ' but the protection level of'
                 ' the permission should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_unknown_new': {
        'title': ('<strong>%s</strong> (%s) 受权限保护，'
                  '但如果应用程序在 API 级别小于 17 的设备上运行，'
                  '则应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别小于 17 的设备上运行，'
                        '则将导出Content Provider(%s)。在这种情况下，'
                        '它仍将受到所分析应用程序中未定义的权限的保护。'
                        '因此，应在定义权限的位置检查权限的保护级别。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission, but the'
                 ' protection level of the permission should be'
                 ' checked if the application runs'
                 ' on a device where the the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_normal_app_new': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，'
                  '但如果应用程序在 API 级别小于 17 的设备上运行，'
                  '则应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别小于 17 的设备上运行，'
                        '则将导出Content Provider (%s)。在这种情况下，'
                        '它仍将受到权限的保护。但是，权限的保护级别设置为normal。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission at the application level '
                 'should be checked, but the protection level of the '
                 'permission if the application runs on a device where'
                 ' the the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_danger_app_new': {
        'title': ('<strong>%s</strong> (%s)  受应用程序级别的权限保护，'
                  '但如果应用程序在 API 级别小于 17 的设备上运行，'
                  '则应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别小于 17 的设备上运行，'
                        '则将导出Content Provider (%s)。在这种情况下，'
                        '它仍将受到权限的保护。但是，权限的保护级别设置为danger。'
                        '这意味着恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限。'),
        'name': ('%s %s is Protected by a permission at the application'
                 ' level, but the protection level of the'
                 ' permission should be checked'
                 ' if the application runs on a device where the the API level'
                 ' is less than 17. [%s] '
                 '[Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signature_app_new': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护'
                  '<br>%s<br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用程序在 API 级别小于 17 的设备上运行，'
                        '则将导出Content Provider (%s)。'
                        '尽管如此，它仍受许可保护。'),
        'name': ('%s %s is Protected by a permission at the application level.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_signatureorsystem_app_new': {
        'title': ('<strong>%s</strong> (%s) 在应用程序级别受权限保护，'
                  '但应检查权限的保护级别。'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'info',
        'description': ('如果应用程序在 API 级别小于 17 的设备上运行，'
                        '则将导出Content Provider(%s)。在这种情况下，'
                        '它仍将受到权限的保护。但是，权限的保护级别设置为 signatureOrSystem。'
                        '建议改用签名级别。签名级别应该足以满足大多数用途，'
                        '并且不依赖于应用程序在设备上的安装位置。'),
        'name': ('%s %s is Protected by a permission at the application'
                 ' level but the protection level of the permission'
                 ' should be checked.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
    'exported_provider_unknown_app_new': {
        'title': ('<strong>%s</strong> (%s) 受应用程序级别的权限保护，'
                  '但如果应用程序在 API 级别小于 17 的设备上运行，则应检查权限的保护级别'
                  '<br>%s <br>[Content Provider, targetSdkVersion >= 17]'),
        'level': 'warning',
        'description': ('如果应用程序在 API 级别小于 17 的设备上运行，'
                        '则将导出Content Provider(%s)。'
                        '在这种情况下，它仍将受到所分析应用程序中未定义的权限的保护。'
                        '因此，应在定义权限的位置检查权限的保护级别。'
                        '如果设置为"normal"或"danger"，则恶意应用程序可以请求并获取权限并与组件交互。'
                        '如果设置为签名，则只有使用相同证书签名的应用程序才能获得权限.'),
        'name': ('%s %s is Protected by a permission at the application level,'
                 ' but the protection level of the permission should be'
                 ' checked  if the application runs on a device where the'
                 ' the API level is less than 17.'
                 ' [%s] [Content Provider, targetSdkVersion >= 17]'),
    },
}
