# Iso2-stream
## Installation
    npm install iso2-stream --save
## Example
```js
const {Pcap, findalldevs} = require('iso2-stream');
var devs = findalldevs(); //find all netdevs from pc
var netDev = new Pcap(devs[0].name); //create new netDev by devs[0].name
netDev.listen("arp");         //listen devs[0] and filter arp
netDev.on("data", (data) => {
    console.log(data);
    netDev.send("10:12:13:14:15:16", "02:03:04:05:06:07", Buffer.from(sendData));  //send packet from 02:03:04:05:06:07 => 10:12:13:14:15:16
    netDev.end();  //close the netDev
})
```
## API
### (method) findalldevs: [Dev]
find all netdevs from pc
#### Dev.name: String
Device name
#### Dev.description: String
Device description
#### Dev.mac: String
Device MAC Address
#### Dev.address: [Address]
Device all IP Address
#### Address.ipaddr: String
IPv4 or APv6 Address
#### Address.netmask: String
IPv4 Netmask
#### Address.broadaddr: String
Broadaddr

### Pcap
The Pcap extends Duplex
#### constructor Pcap(devName:String, option?:any): Pcap
create new netDev by devName

```js
var netDev = new Pcap(devName);
```

#### (method) Pcap.listen(filter?:String, cb?:Function): void
listen netDev

filter: see [tcpdump](https://www.winpcap.org/docs/docs_412/html/group__language.html)

cb: call in listen is ready

#### (method) send(dmac:String, smac:String, data:string|Array|arrayBuffer|Buffer, vlans?:Array<number>): void
send packet

dmac: Destination MAC address

smac: Source MAC address

data: The data to be sent. string|Array|arrayBuffer|Buffer

vlans: null or number or [number].

