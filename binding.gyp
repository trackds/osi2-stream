{
    "targets":[
        {
            "target_name":"pcap_addon",
            "sources":[
                "./src/winpcap/pcap_addon.cc",
                "./src/winpcap/pcapObjFactory.cc",
                "./src/winpcap/commLib.cc"],
            "include_dirs": [
                "<!(node -e \"require('nan')\")",
                "lib/winpcap/include",
                "lib/winpcap/include/pcap",
                "src/winpcap/include"
            ],
            "defines":[
                "HAVE_REMOTE"
            ],
            "conditions":[
                ["OS==\"win\"", {
                    "conditions":[
                        ['target_arch=="x64"',{
                            "libraries": [
                                "-l../lib/winpcap/lib/x64/wpcap",
                                "-l../lib/winpcap/lib/x64/Packet"
                            ]
                        }],
                        ['target_arch=="x86"',{
                            "libraries": [
                                "-l../lib/winpcap/lib/wpcap",
                                "-l../lib/winpcap/lib/Packet"
                            ]
                        }]
                    ]

                }],
                ["OS==\"linux\"", {
                    "libraries": [
                        "lib/winpcap/Lib/libwpcap.a",
                        "lib/winpcap/Lib/libpacket.a"
                    ]
                }]
            ]
        }
    ]
}