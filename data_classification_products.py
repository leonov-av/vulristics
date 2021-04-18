product_data = {
    "Sudo": {
        "prevalence": 0.9,
        "description": "Sudo is a program for Unix-like computer operating systems that allows users to run programs with the security privileges of another user",
        "additional_detection_strings":[ "visudo", "sudoers" ]
    },
    "vSphere Client": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "ESXi": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "RDP": {
        "prevalence": 1,
        "description": "Remote Desktop Protocol",
        "additional_detection_strings": []
    },
    "SMB": {
        "prevalence": 1,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Win32k": {
        "prevalence": 0.9,
        "description": "Windows kernel-mode driver",
        "additional_detection_strings": []
    },
    "Kerberos": {
        "prevalence": 1,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Defender": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "RPC": {
        "prevalence": 0.8,
        "description": "Remote Procedure Call Runtime",
        "additional_detection_strings": []
    },
    "RPC Endpoint Mapper Service": {
        "prevalence":  0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "splwow64": {
        "prevalence": 0.8,
        "description": "splwow64 (printer driver host for 32-bit applications)",
        "additional_detection_strings": []
    },
    "Microsoft Exchange Server": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Office": {
        "prevalence": 0.6,
        "description": "MS Office product",
        "additional_detection_strings": []
    },
    "Microsoft Word": {
        "prevalence": 0.6,
        "description": "MS Office product",
        "additional_detection_strings": []
    },
    "Microsoft Excel": {
        "prevalence": 0.6,
        "description": "MS Office product",
        "additional_detection_strings": []
    },
    "Outlook": {
        "prevalence": 0.6,
        "description": "MS Office product",
        "additional_detection_strings": []
    },
    "Teams": {
        "prevalence": 0.6,
        "description": "MS Office product",
        "additional_detection_strings": []
    },
    "Chakra": {
        "prevalence": 0.6,
        "description": "MS Internet Browser",
        "additional_detection_strings": []
    },
    "Internet Explorer": {
        "prevalence": 0.6,
        "description": "MS Internet Browser",
        "additional_detection_strings": []
    },
    "Microsoft Browser": {
        "prevalence": 0.6,
        "description": "MS Internet Browser",
        "additional_detection_strings": []
    },
    "Scripting Engine": {
        "prevalence": 0.6,
        "description": "MS Internet Browser",
        "additional_detection_strings": []
    },
    "DirectX": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft SharePoint": {
        "prevalence": 0.5,
        "description": "",
        "additional_detection_strings": ['SharePoint']
    },
    "Visual Studio": {
        "prevalence": 0.5,
        "description": "",
        "additional_detection_strings": []
    },
    "Hyper-V": {
        "prevalence": 0.5,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Dynamics 365": {
        "prevalence": 0.5,
        "description": "",
        "additional_detection_strings": []
    },
    "Azure": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    ".NET Core": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": ["NET Core"]
    },
    ".NET Core and Visual Studio": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    ".NET Framework": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "ASP.NET Core": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Azure IoT CLI extension": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Azure Kubernetes Service": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Dataverse": {
        "prevalence": 0.2,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Dynamics Business Central": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Edge for Android": {
        "prevalence": 0.1,
        "description": "Web browser",
        "additional_detection_strings": []
    },
    "Microsoft Edge (Chromium-based)": {
        "prevalence": 0.8,
        "description": "Web browser",
        "additional_detection_strings": []
    },
    "Microsoft Teams iOS": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows": {
        "prevalence": 0.9,
        "description": "Windows Kernel",
        "additional_detection_strings": []
    },
    "Windows Codecs Library": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows VMSwitch": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft.PowerShell.Utility Module WDAC": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "PFX Encryption": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Raw Image Extension": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "VP9 Video Extensions": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Package Managers Configurations": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Skype for Business and Lync": {
        "prevalence": 0.9,
        "description": "",
        "additional_detection_strings": []
    },
    "Sysinternals PsExec": {
        "prevalence": 0.8,
        "description": "0.9",
        "additional_detection_strings": []
    },
    "System Center Operations Manager": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Visual Studio Code": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    "Visual Studio Code npm-script Extension": {
        "prevalence": 0.2,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Address Book": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Backup Engine": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Camera Codec Pack": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Console Driver": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows DNS Server": {
        "prevalence": 0.9,
        "description": "",
        "additional_detection_strings": []
    },
    "NTFS": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows DirectX": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Event Tracing": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Fax Service": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Graphics Component": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Installer": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Kernel": {
        "prevalence": 0.9,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Local Spooler": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Mobile Device Management": {
        "prevalence": 0.7,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Network File System": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows PKU2U": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Remote Procedure Call": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows TCP/IP": {
        "prevalence": 0.9,
        "description": "",
        "additional_detection_strings": []
    },
    "Windows Trust Verification API": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Active Template Library": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },
    "Azure Active Directory Pod Identity": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },
    "Microsoft Internet Messaging API": {
            "prevalence": 0.6,
            "description": "",
            "additional_detection_strings": []
        },
    "Bot Framework SDK": {
            "prevalence": 0.4,
            "description": "",
            "additional_detection_strings": []
        },
    "Diagnostics Hub Standard Collector": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },
    "GDI+": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },
    "HEVC Video Extensions": {
            "prevalence": 0.7,
            "description": "",
            "additional_detection_strings": []
        },
    "Microsoft DTV-DVD Video Decoder": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },
    "Microsoft Edge (HTML-based)": {
            "prevalence": 0.8,
            "description": "Web browser",
            "additional_detection_strings": []
        },
    "Google Chrome": {
        "prevalence": 0.8,
        "description": "Web browser",
        "additional_detection_strings": []
    },
    "Microsoft Office": {
            "prevalence": 0.6,
            "description": "",
            "additional_detection_strings": []
        },
    "Microsoft SQL": {
            "prevalence": 0.6,
            "description": "",
            "additional_detection_strings": []
        },
    "Windows Media Foundation": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },
    "NTLM": {
            "prevalence": 0.9,
            "description": "",
            "additional_detection_strings": []
        },
    "Remote Procedure Call Runtime": {
            "prevalence": 0.9,
            "description": "",
            "additional_detection_strings": []
        },
    "TPM Device Driver": {
            "prevalence": 0.8,
            "description": "",
            "additional_detection_strings": []
        },

    "Application Virtualization": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Azure Sphere": {
        "prevalence": 0.4,
        "description": "",
        "additional_detection_strings": []
    },
    "Azure Virtual Machine": {
        "prevalence": 0.4,
        "description": "",
        "additional_detection_strings": []
    },
    "Azure": {
        "prevalence": 0.4,
        "description": "",
        "additional_detection_strings": []
    },
    "Git": {
        "prevalence": 0.4,
        "description": "",
        "additional_detection_strings": []
    },
    "Git for Visual Studio": {
        "prevalence": 0.4,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Office ClickToRun": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Power BI": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft PowerPoint": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Visio": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },
    "OpenType Font Parsing": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Quantum Development Kit for Visual Studio Code": {
        "prevalence": 0.5,
        "description": "",
        "additional_detection_strings": []
    },
    "Remote Access API": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Storage Spaces Controller": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "User Profile Service": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Visual Studio Code ESLint Extension": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },
    "Visual Studio Code Java Extension Pack": {
        "prevalence": 0.6,
        "description": "",
        "additional_detection_strings": []
    },

    "Windows (modem.sys)": {
        "prevalence": 0.9,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows AppX Deployment Extensions": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Bluetooth": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows CSC Service": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows CryptoAPI": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows DNS Query": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Docker": {
        "prevalence": 0.7,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Event Logging Service": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Fax Compose Form": {
        "prevalence": 0.7,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows GDI+": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Hyper-V": {
        "prevalence": 0.6,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows InstallService": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows LUAFV": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Multipoint Management": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows NT Lan Manager Datagram Receiver Driver": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Print Spooler": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Projected File System FS Filter Driver": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Remote Desktop": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Remote Desktop Protocol Core": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Remote Procedure Call Runtime": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Runtime C++ Template Library": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Update Stack": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows WLAN Service": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows WalletService": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },

    "Windows Folder Redirection": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows 10 Update Assistant": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows ActiveX Installer Service": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Admin Center": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows App-V Overlay Filter": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Container Execution Agent": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Error Reporting": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Extensible Firmware Interface": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Media Photo Codec": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows NAT": {
        "prevalence": 0.9,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Overlay Filter": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Projected File System": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows UPnP Device Host": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Update Service": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Update Stack Setup": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows User Profile Service": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Virtual Registry Provider": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows AppX Deployment Server": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Application Compatibility Cache": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Early Launch Antimalware Driver": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Media Video Decoder": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Resource Manager PSM Service Extension": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Secure Kernel Mode": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Services and Controller App": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows Speech Runtime": {
        "prevalence": 0.8,
        "description": "Windows component",
        "additional_detection_strings": []
    },
    "Windows WLAN AutoConfig Service": {
        "prevalence": 0.8,
        "description": "Windows сomponent",
        "additional_detection_strings": []
    },
}