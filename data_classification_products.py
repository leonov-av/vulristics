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
    "Word": {
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
        "additional_detection_strings": []
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
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Teams iOS": {
        "prevalence": 0.3,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Windows": {
        "prevalence": 0.9,
        "description": "Windows Kernel",
        "additional_detection_strings": []
    },
    "Microsoft Windows Codecs Library": {
        "prevalence": 0.8,
        "description": "",
        "additional_detection_strings": []
    },
    "Microsoft Windows VMSwitch": {
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
        "prevalence": 0,
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
}