var pcap_addon = require('../../build/Release/pcap_addon.node');
process.on('message', (m) => {
    console.log('CHILD got message:', m);
});

var filter = process.argv[2];
var devName = process.argv[3];

var dev = pcap_addon.openDev(devName);

if (filter && (filter != "undefined") && (filter != "null") && (typeof filter === "string")) {
    dev.SetFilter(filter);
}

process.send({ready:true});
dev.read((err, data) => {
    process.send({error:err,data:data});
});