const {Pcap, findalldevs} = require('../');
const {assert} = require("chai");

let devs = null;
let netDev = null;
const sendData = [0x00,0x11,0x22,0x33,0x44,0x55,
    0x00,0x11,0x00,0x11,0x00,0x11,0x00,0x11,0x11,0x11,0x22,0x44,
    0x11,0x11,0x22,0x44,0x11,0x11,0x22,0x44,0x11,0x11,0x22,0x44,0x11,0x11,0x22,0x44,
    0x11,0x11,0x22,0x44,0x11,0x11,0x22,0x44,0x11,0x11,0x22,0x44,0x11,0x11,0x22,0x44]
describe("find devs test", () => {
    it("findalldevs", function() {
        this.slow(1000);
        devs = findalldevs();
        assert.isArray(devs,"devs must is a Array");
    })
});

describe("Send and Receive Packet test", () => {
    it("open the first network device", () => {
        netDev = new Pcap(devs[0].name);
        assert.isOk(netDev, "new Pcap fail");
        assert.isOk(netDev.dev, "open device fail");
        assert.isOk(netDev.dev.send, "device is invalid");
    });

    it("Capture a package", function(cb) {
        this.slow(10000);
        this.timeout(10000);
        netDev.listen();
        netDev.once("data", (data) => {
            assert.isOk(data);
            cb();
        })
    });
    it("set arp filter and Capture a package", function(cb) {
        this.slow(10000);
        this.timeout(10000);
        netDev.listen("arp");
        netDev.once("data", (data) => {
            assert.isOk(data);
            assert.equal(data.readUInt16BE(12), 0x0806, `Capture a not arp package`);
            cb();
        })
    });
-
    it("send a untag packet", function(cb) {
        this.slow(10000);
        this.timeout(10000);
        netDev.listen(() => {
            netDev.once("data", (data) => {
                assert.isOk(data);
                cb()
            })
            netDev.send("10:12:13:14:15:16", "02:03:04:05:06:07", Buffer.from(sendData));
        });
    });

    it("send a single tag packet", () => {
        netDev.send("10:12:13:14:15:16", "02:03:04:05:06:07", Buffer.from(sendData), 0x1234);
    });

    it("send a double tag packet", () => {
        netDev.send("10:12:13:14:15:16", "02:03:04:05:06:07", Buffer.from(sendData), [0x1234,0x4321]);
    });

    it("write a packet", () => {
        netDev.write(Buffer.from(sendData));
    })
    it("close", () => {
        netDev.end();
    });
});