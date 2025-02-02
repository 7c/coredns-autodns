# coredns-autodns plugin
autodns loads zones from redis server and can resolve them, under the hood it is using [coredns-redis](https://github.com/codysnider/coredns-redis) plugin.You should always use [acl](https://coredns.io/plugins/acl/) plugin with autodns plugins for access control. autodns main functionality is to register subdomains of given zones with a simple keyword `_reg.` as prefix. It is recommended to listen to a vpn/tailscale/zerotier network and allow only these trusted networks with 'register.network' directive.it can set `register.deny` to deny registration of some subdomains they might be used for other purposes. It is planned to be loose, meaning you can have ns1 and ns2 servers and they will be using their own redis-servers and zones. It is recommended to have 2 seperate nameservers for same domain on different datacenters. Every client should register at both ns1 and ns2. It is fine to have custom tlds which are not resolveable from the public internet, but i prefer to have dedicated domain for this purpose which can be resolved from the public internet. i would block ns1,ns2,ns3, www from registering, allow only trusted networks registration and serve only that domain to be resolved from the public internet and never allow "." to be served. `fallthrough` support for records plugin is added to https://github.com/7c/coredns-records plugin, in case you need to serve static records.

## how to build
this plugin is designed to be built with coredns build system. Check https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/ for more information. But basically you should clone the coredns repo and insert 'autodns:https://github.com/7c/coredns-autodns' to the `plugin.cfg` file and build it with `make` command inside the coredns directory.
```
git clone https://github.com/coredns/coredns
cd coredns
# echo "records:github.com/7c/coredns-records" >> plugin.cfg
echo "autodns:github.com/7c/coredns-autodns" >> plugin.cfg
apt install -y make
make
#./coredns -plugins | grep records
./coredns -plugins | grep autodns

```


## autodns functionality


## register
```bash
## register at ns1.example.com
host1 > host -t TXT _reg.host1.example.com @100.64.0.1
## register at ns2.example.com
host1 > host -t TXT _reg.host1.example.com @100.64.0.2

## lookup now should return the ip address available from public internet
$ host host1.example.com
## if you have choosen to use custom tlds, you should lookup like this
$ host host1.custom.tld 100.64.0.1
```

~~~
records {
    ns1 3600 IN A  1.2.3.4
    ns2 3600 IN A 1.2.3.5
    fallthrough
}
autodns example.com {
    ## redis server connection configuration
    address ADDR
    password PWD
    prefix PREFIX
    suffix SUFFIX
    connect_timeout TIMEOUT
    read_timeout TIMEOUT
    ttl TTL
    ## debugging
    verbose
    ## this will create SOA RR for the zone if it doesn't exist yet
    autocreate ZONE1
    autocreate ZONE2
    ## networks to allow registration from
    register.network 100.64.0.0/16
    register.network 127.0.0.1/32
    ## subdomains ns1.example.com, ns2.example.com, ns3.example.com, www.example.com are not allowed to register
    register.deny "ns1"
    register.deny "ns2"
    register.deny "ns3"
    register.deny "www"
}

~~~

* `address` is redis server address to connect in the form of *host:port* or *ip:port*.
* `password` is redis server *auth* key, default is empty
* `connect_timeout` time in ms to wait for redis server to connect, default is 100ms
* `read_timeout` time in ms to wait for redis server to respond, default is 100ms
* `ttl` default ttl for dns records, default is 300s
* `prefix` add PREFIX to all redis keys, default is empty
* `suffix` add SUFFIX to all redis keys, default is empty
* `verbose` print debug information, default is false   
* `autocreate` create zone in redis if it doesn't exist, default is false
* `register.network` networks to allow registration from, default is empty and no registration is allowed
* `register.deny` subdomains to deny registration from, default is empty and all subdomains are allowed to be registered
## examples

~~~ corefile
. {
    autodns example.com {
        address localhost:6379
        password foobared
    }
}
~~~

## reverse zones

reverse zones is not supported yet

## proxy

proxy is not supported yet

## zone format in redis db

### zones

each zone is stored in redis as a hash map with *zone* as key

~~~
redis-cli>KEYS *
1) "example.com."
2) "example.net."
redis-cli>
~~~

### dns RRs 

dns RRs are stored in redis as json strings inside a hash map using address as field key.
*@* is used for zone's own RR values.

#### A

~~~json
{
    "a":{
        "ip" : "1.2.3.4",
        "ttl" : 360
    }
}
~~~

#### AAAA

~~~json
{
    "aaaa":{
        "ip" : "::1",
        "ttl" : 360
    }
}
~~~

#### CNAME

~~~json
{
    "cname":{
        "host" : "x.example.com.",
        "ttl" : 360
    }
}
~~~

#### TXT

~~~json
{
    "txt":{
        "text" : "this is a text",
        "ttl" : 360
    }
}
~~~

#### NS

~~~json
{
    "ns":{
        "host" : "ns1.example.com.",
        "ttl" : 360
    }
}
~~~

#### MX

~~~json
{
    "mx":{
        "host" : "mx1.example.com",
        "priority" : 10,
        "ttl" : 360
    }
}
~~~

#### SRV

~~~json
{
    "srv":{
        "host" : "sip.example.com.",
        "port" : 555,
        "priority" : 10,
        "weight" : 100,
        "ttl" : 360
    }
}
~~~

#### SOA

~~~json
{
    "soa":{
        "ttl" : 100,
        "mbox" : "hostmaster.example.com.",
        "ns" : "ns1.example.com.",
        "refresh" : 44,
        "retry" : 55,
        "expire" : 66
    }
}
~~~

#### CAA

~~~json
{
    "caa":{
        "flag" : 0,
        "tag" : "issue",
        "value" : "letsencrypt.org"
    }
}
~~~

#### example

~~~
$ORIGIN example.net.
 example.net.                 300 IN  SOA   <SOA RDATA>
 example.net.                 300     NS    ns1.example.net.
 example.net.                 300     NS    ns2.example.net.
 *.example.net.               300     TXT   "this is a wildcard"
 *.example.net.               300     MX    10 host1.example.net.
 sub.*.example.net.           300     TXT   "this is not a wildcard"
 host1.example.net.           300     A     5.5.5.5
 _ssh.tcp.host1.example.net.  300     SRV   <SRV RDATA>
 _ssh.tcp.host2.example.net.  300     SRV   <SRV RDATA>
 subdel.example.net.          300     NS    ns1.subdel.example.net.
 subdel.example.net.          300     NS    ns2.subdel.example.net.
 host2.example.net                    CAA   0 issue "letsencrypt.org"
~~~

above zone data should be stored at redis as follow:

~~~
redis-cli> hgetall example.net.
 1) "_ssh._tcp.host1"
 2) "{\"srv\":[{\"ttl\":300, \"target\":\"tcp.example.com.\",\"port\":123,\"priority\":10,\"weight\":100}]}"
 3) "*"
 4) "{\"txt\":[{\"ttl\":300, \"text\":\"this is a wildcard\"}],\"mx\":[{\"ttl\":300, \"host\":\"host1.example.net.\",\"preference\": 10}]}"
 5) "host1"
 6) "{\"a\":[{\"ttl\":300, \"ip\":\"5.5.5.5\"}]}"
 7) "sub.*"
 8) "{\"txt\":[{\"ttl\":300, \"text\":\"this is not a wildcard\"}]}"
 9) "_ssh._tcp.host2"
10) "{\"srv\":[{\"ttl\":300, \"target\":\"tcp.example.com.\",\"port\":123,\"priority\":10,\"weight\":100}]}"
11) "subdel"
12) "{\"ns\":[{\"ttl\":300, \"host\":\"ns1.subdel.example.net.\"},{\"ttl\":300, \"host\":\"ns2.subdel.example.net.\"}]}"
13) "@"
14) "{\"soa\":{\"ttl\":300, \"minttl\":100, \"mbox\":\"hostmaster.example.net.\",\"ns\":\"ns1.example.net.\",\"refresh\":44,\"retry\":55,\"expire\":66},\"ns\":[{\"ttl\":300, \"host\":\"ns1.example.net.\"},{\"ttl\":300, \"host\":\"ns2.example.net.\"}]}"
15) "host2"
16)"{\"caa\":[{\"flag\":0, \"tag\":\"issue\", \"value\":\"letsencrypt.org\"}]}"
redis-cli>
~~~
