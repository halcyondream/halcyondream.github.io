---
title: Circumventing TLS
---

# Scope and Purpose

This document provides two methods and three
architectures which would facilitate HTTPS traffic interception: getting
request and response data in cleartext. All approaches assume that
strong TLS is used and cannot be fundamentally broken. Further, it
assumes that the IoT devices themselves cannot be modified, nor can
their firmware be dumped. (Note: The mitm interceptors will work better
if a device’s private key and certificate are exfiltrated, but this is
not strictly needed because all devices are behind the same subnet.)

This should provide the decrypted request-response
pairs, which a PCAP file will not necessarily allow you to retrieve from
captured TLS packets. That is not to undermine the use of something like
tcpdump on a central gateway. Rather, the “methods to decrypt” should
complement such a solution, with the intention of yielding plaintext TLS
traffic.

# Methods to decrypt

With TLS 1.3, there are two primary approaches to circumventing TLS in
order to transparently intercept traffic. Both methods are explained in three
different architectures in the next section. Neither method touches on
traffic analysis. This is best accomplished using machine learning. Such
a discussion is out of scope.

## Capturing Session Keys

Tools like SSLKeyLogger can
capture session keys at the endpoint itself. This is designed for client
applications. However, the shared object can hook into services and dump
session keys for a web service.

The source code for the shared object is located here: https://git.lekensteyn.nl/peter/wireshark-notes. 

A walkthrough for hooking into an Apache2 web service is explained here:
https://security.stackexchange.com/a/215397

## Leveraging a transparent “interceptor”

An application that decrypts-and-forwards packets can
sit between an endpoint and some other network. The next section in this
document discusses two approaches to realize this goal (Architectures 2
and 3). 

An oversimplified application architecture might
resemble the following:

![](/assets/2022-06-26/interceptor-architecture.png)

This should work for an IoT device that is under your
own control. Consider that, if this sat between an attacker and, say,
Google.com, the certificate mis-match would raise an alert in the
attacker’s browser. However, since the device is on your own subnet,
this should work transparently.

Finally, consider that “IoT device” can include a
“smart device” or an IoT hub. The use of hubs is becoming increasingly
popular in home IoT environments. 

Note: The security and accessibility benefits
should be obvious and are not noted here at this time. Likewise, the
security and implementation concerns are also obvious and are also not
noted here at this time. Suffice it to say, an IoT hub would make a
great target for an attacker if it were poorly configured, designed, or
implemented.

### Other implementation ideas

A node on the network might accomplish the same goal by
using something like PolarProxy or mitmproxy. Please note that these
tools will require extensive configuration. It may prove easier to write
something from scratch. 

# Attack Surface Architectures

This document assumes that an approved entity is capturing HTTPS traffic
on a network with N number of
IoT devices. The following architectures will create the conditions
needed for transparent HTTPS encryption and decryption. They are all
transparent to the attacker and require no client-side
configuration.

Architectures 1 and 2 show how the attacker might
leverage an IoT hub to attack devices behind the hub. They assume that
the attacker is connecting to the Hub on port 443, the only open port on
the gateway/router. This architecture best represents an “ideal” IoT
home, whereby an authorized entity can access their IoT devices through
a hub, which listens on port 443, the only WAN-facing port.

Architecture 3 will faithfully capture
requests/responses as close as possible to the endpoint (the IoT device
itself). This setup assumes that the attacker is on the subnet and can
attack each IoT endpoint “directly” (through the node that is
intercepting and logging request-response pairs). This architecture best
represents how an attacker who has infiltrated the network might try to
attack the devices.

Finally, it may serve the user to combine architectures
2 and 3. This will provide a comprehensive amount of request-response
data. However, this will require more routing and subnetting, and may
introduce unwanted overhead. 

## Architecture 1: Intercept on the IoT hub

If the IoT hub is open-source or home-grown, a developer could hook the
SSLKeyLog shared object into the Hub’s service. This can intercept the
session keys for streams between the WAN and the HUB, as well as all
streams from the HUB to N number of IoT devices. 

![](/assets/2022-06-26/architecture1.png)

Pros: This best resembles the
current direction of IoT security and device relationships. Consolidates
the number of open ports facing the WAN. You can plug the session keys
into a corresponding PCAP file with the TLS traffic and view the
cleartext request-response data in an application like Wireshark.

Cons: If you can neither hook
the SSLKeyLog.so nor extract the pk/cert , this solution is
infeasible.

## Architecture 2: MitM just before the Hub.

If you cannot install or hook SSLKeyLogger on the hub,
you can set up a listener to transparently intercept and log
request-response pairs. Such an application works like a mitm proxy, but
MUST be fully transparent to the WAN; notably, it MUST NOT require the
client to perform any kind of browser configuration. 

This model assumes you have the hub’s private key and certificate. If
this is infeasible, the intercepting application MUST be engineered in
such a way that it does not reveal (to the attacker) that it is using a different private
key than the hub itself. Understand that this is integral to TLS; it is
essentially what prevents this kind of interception from happening
between a user and a site like Google.com. 

With that said, an engineer whose devices are on their
own subnet can pull this off. Just use thorough and common-sense testing
to ensure that an attacker cannot detect that there is a node capturing
traffic.

![](/assets/2022-06-26/architecture2.png)

Pros: Transparently capture the
request and response pairs between the WAN and Hub. Since the hub will
make requests to the devices on behalf of the user/attacker, you can
determine how the attacker intends to exploit the IoT device and the
hub. This is best for a system that employs a hub, which allows no
access to or control over the hub’s firmware.

Cons: Will not provide data on
how the attacker would directly attack the IoT device itself, because
the hub sits between the attacker and the device. This is problematic in
the event that an attacker infiltrates the private network: a given
assumption in zero-trust architectures.


## Architecture 3: Capture just before the endpoint

This architecture will set up a listener just before
each endpoint. The interceptor is another node on the network.
Authorized and unauthorized entities alike must pass through this node
in order to contact the IoT device itself. (On a honeypot, all entities
are unauthorized.) 

This will yield the most accurate representation of how
an attacker, or malware like Mirai, might try to exploit HTTPS on an IoT
device. The biggest downside is that it requires the private key and
certificate for the IoT device; if the developer cannot get this, the
interception is not possible. Further, each IoT device will require a
separate node (for example, a docker container, VM, or physical device
like a Raspberry Pi); this will understandably introduce
overhead.

Note that, if the attacker has full control over the
IoT device, they can leverage SSLKeyLogger to dump the session keys on
the endpoint itself. Of course, since many IoT devices use small,
proprietary firmware, this is likely infeasible. A workaround is to
create the IoT device from scratch: for example, using a RaspberryPi,
known endpoints and behaviors, and historic, captured traffic to the
real IoT device which this one is imitating.

One massive caveat with this approach is that many IoT vendors are
leveraging private keys and certificates in their device endpoint and in the phone application itself.
If this is the case, the only workaround is to break TLS. With that
said, understand that the attacker may not be able to launch an attack
with any means beside the authorized, legitimate app. So, such devices
may be less susceptible to tactics and procedures which are commonly
used against web applications (for example, using Burp Suite).

In the following diagram, note that the attacker must
pass through the interceptor; both clients are on the OpenWRT subnet
(192.168.1.255). However, the IoT device connects to the interceptor
directly via some new subnet (10.0.0.255). Implementation details for
this second subnet are not discussed here. The point is to not make the
device publicly available to the “real” subnet, while nonetheless having
the device appear “transparent” to an attacker.

![](/assets/2022-06-26/architecture3.png)

Pros: This will yield the most
accurate data about each device.

Cons: The additional subnet (10.0.0.M in the diagram) will require
more configuration and could introduce more overhead.

## Combination of Architectures 2 and 3

This approach will place a listener between the wan and
hub, and between the hub and each device.
If feasible (with respect to time and financial means), the author
recommends implementing a network like this because it will yield the
most cleartext data from all TLS requests-responses behind the gateway.

Pros: Combining architectures 2
and 3 will yield the most data.

Cons: This will have the same concerns regarding
configuration and overhead as noted in Architecture 2. Further, this
will spoof packets between the device and the hub; if the hub detects
this, it may cause accessibility issues. (Note:
Ideally, the interceptor will not have this caveat, but it is still
worth reiterating.)

# Considerations

This document is written with HTTPS in mind. An IoT
network that relies on non-HTTPS traffic may not benefit from the
preceding discussion.

Each “interceptor” node represents a single point of
failure for communication to and from the device. Scaling, redundancy,
and similar features are not covered here. Although this document was
written with FOSS solutions in mind, concerns related to SPOF may
introduce some cost implications.

An interceptor that decrypts-then-forwards HTTPS
traffic must faithfully reconstruct the entire HTTP Request (from the
attacker) before sending it to the intended endpoint (the IoT device).
Failure to do so may leave evidence that there is a system between the
attacker and the device. This would compromise the “transparency”
aspect.

As noted (but bears repeating), take care to test
whether an interceptor’s certificate will raise any alerts in the
attacker’s browser. An obvious example would arise if you tried to use
such an interceptor to capture traffic between the
attacker and, say, Google. The mismatch in keys/certificates would raise
an alert in the attacker’s browser and thereby compromise transparency
(in addition to flat-out failing to load content in the browser). Again,
take special care to test for these differences before opening the lab
to the WAN.

Finally, if you just want a comprehensive packet-capture (like in
tcpdump on a router), try to ways to force HTTP on the IoT devices. As
HTTPS is becoming more and more popular for low-end devices, this
solution may prove infeasible as time goes on. Still, if it works right
now, for your particular setup, it may prove substantially easier than any of the
strategies explained here.

