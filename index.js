const pcap_addon = require('./build/Release/pcap_addon.node');
const {fork} = require("child_process");
const { Duplex } = require('stream');
const path = require("path");

class Pcap extends Duplex {
    constructor(devName, options) {
        super(options);
        if (typeof devName === 'string')
        {
            this.devName = devName;
            this.dev = pcap_addon.openDev(devName);
            this.data = [];
        }
        else
            throw new Error("denName must be String");
    }
    /**
     * @param {string} [filter]
     * @param {Function} [cb]
    */
    listen(filter, cb) {
        if (this.cp) {
            this.cp.kill();
            this.cp = null;
        }
        let _filter = "";
        let _cb = null;
        if (typeof filter === "string") {
            _filter = filter;
        }
        if (filter instanceof Function) {
            _cb = filter;
        } else if (cb instanceof Function) {
            _cb = cb;
        }

        this.cp = fork(path.join(__dirname,"./src/js/receive.js"), [_filter, this.devName]);
        this.cp.on("message", (m) => {
            let errmsg = m.error;
            if (m.ready) {
                if (_cb instanceof Function) {
                    _cb();
                }
                return;
            }
            if (errmsg) {
                throw new Error(errmsg);
            }
            this.data.push(Buffer.from(m.data.data));
            this.emit("receive");
        });
    }
    /**
     * @param {string} dmac
     * @param {string} smac
     * @param {string|Array|arrayBuffer|Buffer} data
     * @param {number|Array<number>} [vlans]
    */
    send(dmac, smac, data, vlans){
        if (dmac && smac && data) {
            let dmacData = dmac.split(':').map((num)=>parseInt(num,16));
            let smacData = smac.split(':').map((num)=>parseInt(num,16));

            if (dmacData.length !== 6 || smacData.length !== 6) {
                throw new Error("MAC address format error");
            }

            let sbuf = Buffer.concat([Buffer.from(dmacData),Buffer.from(smacData)]);
            let bData = data instanceof Buffer ? data : Buffer.from(data);
            let _vlans = vlans instanceof Array ? vlans: [vlans];
            for(let vlan of _vlans) {
                if (!vlan) {
                    continue;
                }
                let vlanb = Buffer.allocUnsafe(4);
                vlanb.writeUInt16BE(0x8100, 0);
                vlanb.writeUInt16BE(vlan, 2);
                sbuf = Buffer.concat([sbuf, vlanb]);
            }
            sbuf = Buffer.concat([sbuf, bData]);
            this.write(sbuf);
        } else {
            throw new Error("must has dmac smac data");
        }
    }
    _write(chunk, encoding, callback) {
        let data = Buffer.from(chunk, encoding);
        this.dev.send(data);
        callback();
    }
    
    _read(size) {
        let data = this.data.shift();
        if (data) {
            this.push(data.slice(0, size));
        } else {
            this.once("receive", () => {
                let data = this.data.shift();
                this.push(data.slice(0, size));
            });
        }
    }
    _final(cb) {
        this.cp.kill();
        this.cp = null;
        this.dev.close();
        cb();
    }
}

module.exports.Pcap = Pcap;
module.exports.findalldevs = pcap_addon.findalldevs;