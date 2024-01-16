---
layout: post
title: TryHackMe AWS S3 Walkthrough
date: 2024-01-16
---

This guide will walk you through the AWS S3 labs' campaign. The intention is to lay out the attack steps as a methodology with a more natural flow than the labs, which fragment the process as it is broken into different sections.

Our scope is *bestcloudcompany.org* along with all testable AWS components. We will try to focus on all aspects of the campaign, keeping an eye towards AWS-specific components as they appear. 

## Background and Methodology

The *TryHackMe* labs offer a few approaches for targeting S3 buckets specifically during an assessment:

- **Subdomain Enumeration**. This can lead, either directly or indirectly, to a valid and open S3 bucket. The usefulness of such buckets will rely entirely on their permissions&mdash;or, rather, their *lack* of permissions. You can leverage tools like the [Crt.sh](https://crt.sh) to help with your enumeration efforts.
- **DNS Reconnaissance**. This can help you map IPs to valid AWS Services and, conversely, URLs to such IPs. You can use tools like *nslookup* for IPs and domains or subdomains. AWS Service artifacts will include key terms like "ec2" or "s3."

We will leverage these hints in order to discover any public buckets as appropriate.

Although this is intended for offensive strategy for S3 buckets, try to approach this as a more "holistic" penetration test or application assessment. Approaching such an assessment without assumptions, even in a lab, will provide you with an opportunity to see the larger picture and will lead to better findings. This will serve you in real-world situations and, in my personal opinion, serve to enrich the labs provided by THM.

## Reconnaissance

The THM guide recommends two approaches for S3 bucket discovery: DNS Recon and Subdomain enumeration. These are both useful for discovering evidence of AWS services.

Before we approach these, let's see what our scoped domain is *supposed* to do. This will give us an idea of the developers' intentions and help us understand any blind spots along the way.

### Open services

You can run *nmap* against the URL:

```
~$ nmap -Pn bestcloudcompany.org
...
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
```

The only open ports are web ports. This is incredibly useful as it narrows the scope of our reconnaissance and, later, our exploit approaches. These results also shed some light on the developers' intentions, as well as any assumptions or pitfalls.

In short, we have a web application. Let's check it out.

### Application

First, let's open *bestcloudcompany.org* in a browser. Observe that this is a landing page with a blog and some small capabilities.

Scroll down and observe that this is "powered by WordPress." This is a bad sign already since WordPress is notoriously insecure by default and the platform is the subject of many AppSec trainings. That aside, it also means that some WordPress functionality may be available to the public internet. For example, try to open http://bestcloudcompany.org/wp-login.php, a well-known WordPress login URI.

The login page loads. If you were doing a more AppSec-focused assessment, you might try password brute-forcing or injection attacks to bypass this page. 

You are welcome to play around with any other WordPress quirks or functionalities. In this case, let's make a note of this capability and return to it later. 

Note that you could use a tool like Burp Suite or OWASP ZAP to enumerate both traffic and page content. This would be appropriate to discovering open and insecure services, including AWS Services, through page content or request-response history. Preferably, you would want to walk through the webapp yourself, and leverage crawlers as appropirate.

In my case, no evidence of AWS Services appeared in the the page history or content. (However, I have performed assessments where the developers refer directly to S3 buckets, so it's worth trying this in a real-world web pentest.) This is a dead end. Let's move on to other recon tactics.

### Subdomain Enumeration

Now, let's try to find any subdomains associated with the site or organization. Often, subdomains point to additional resources for the organization, including webpage content, webapp resources, and separate applications. Sometimes, they point to storage units that hold backups or secrets.

Let's start by using *Crt.sh* to enumerate any subdomains discovered by certificate transparency logs. Open the site and search for *bestcloudcompany.org*.

Observe that *assets.bestcloudcompany.org* appears. Based solely on the name, we can speculate whether this is used to store information for the organization's website. 

There are other subdomains listed, and you are welcome to try them. None of them loaded anything for me (*nmap*, browser, etc.), so they weren't actionable in this assessment. Let's proceed with the *assets* subdomain.

A simple *nmap* scan will report that, again, ports 80 and 443 are open. However, if you try to load these in the browser, nothing happens. Still, this is indicative that *something* is there, so let's try to push this a little further.

### DNS Reconnaissance

First, let's use *nslookup* on the *bestcloudcompany.org* domain. Take one of the IPs and then perform the same thing to view more information about who is hosting this:

```
# Look up the scoped URL.
~$ nslookup bestcloudcompany.org
Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	bestcloudcompany.org
Address: 44.203.62.152

# Look up the IP from the previous answer
~$ nslookup 44.203.62.152
Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
152.62.203.44.in-addr.arpa	name = ec2-44-203-62-152.compute-1.amazonaws.com.

Authoritative answers can be found from:
```

In this case, the *name* in the second answer shows some evidence of an AWS EC2 service. This tells us that we are working with a web application hosted from an EC2 instance. Since such an instance is effectively a full-on virtual machine, we can further speculate that, if we can find a way in, we can leverage the system's inbuilt tools (for example, the Linux command line) for lateral movement or secrets enumeration.

Now, let's take the *assets* subdomain and perform a similar search:

```
~$ nslookup assets.bestcloudcompany.org
Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	assets.bestcloudcompany.org
Address: 18.239.225.25
Name:	assets.bestcloudcompany.org
Address: 18.239.225.57
Name:	assets.bestcloudcompany.org
Address: 18.239.225.109
Name:	assets.bestcloudcompany.org
Address: 18.239.225.94

~$ nslookup 18.239.225.25
Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
25.225.239.18.in-addr.arpa	name = server-18-239-225-25.mia3.r.cloudfront.net.
```

The second answer's *name* reveals that the *assets* subdomain is behind AWS CloudFront, a CDN that provides other features like WAF and Firewall rules. You are welcome to poke around at this as an exercise, but be careful not to trigger any WAF protections, such as extreme rate-limiting or IP blocklisting. For now, let's try a different approach.

As a heuristic, "assets" may indicate a collection or storage unit with files or objects, regardless of whether they are used by the web application or for some other purpose. We also know that this is behind a CloudFront CDN. A common AWS example of this is hiding an S3 bucket behind CloudFront to limit who can access those files or objects.

With this in mind, we can hypothesize that, if we can find (or guess) an S3 URI that is publicly accessible, then we can access the bucket itself. Again, the usefulness of this will depend on whether or not the objects in the buckets are open or restricted. (As a further consideration, this *could* also indicate an EC2 instance with a file server or a web server that provides the assets. However, an S3 bucket would accomplish the same thing with less effort, so we can push in that direction first.)

## Exploitation with AWS services

Let's recap the first section. First, we discovered a public-facing web application running on an EC2 instance. We also found an *assets* subdomain whose purpose is not clear at this time.

During recon, we also gathered a few data points that suggest we are working with an AWS application: the existence of EC2 and CloudFront. Let's try to push these in order to see if there are any public endpoints, files, or services exposed. Knowing that it is common to hide S3 buckets behind CloudFront, we can try to determine if there is any way to access a bucket associated with the *assets* subdomain, and see what else we can do.

### Trying a common S3 naming convention

Although there are lists with S3 URL patterns, the default format at the time of writing is:

```
https://<bucketname>.s3.amazonaws.com/<filename>
```

(You can test this in an AWS S3 bucket of your own and test if the convention has changed.)

An organization may follow a consistent convention for naming their buckets. The specifics will depend on the organization. However, suppose an organization chooses to name their buckets based on a domain or subdomain under their control. Using this, we can try to form an S3 URL like:

```
https://assets.bestcloudcompany.org.s3.amazonaws.com
```

If the bucket is availble to the public, then opening this in a browser will return an XML with the contents of the buckets or with an "Access Denied" error. In this case, it returns the following, which indicates that this is in fact an S3 bucket whose contents are available to the public web:

```xml
<ListBucketResult>
<Name>assets.bestcloudcompany.org</Name>
<Prefix/>
<Marker/>
<MaxKeys>1000</MaxKeys>
<IsTruncated>false</IsTruncated>
<Contents>
<Key>ami-056a6742115906e8c.bin</Key>
<LastModified>2022-05-04T20:17:01.000Z</LastModified>
<ETag>"65247a1c5755517a32636c78de3d624a-177"</ETag>
<Size>1483486006</Size>
<StorageClass>STANDARD</StorageClass>
</Contents>
<Contents>
<Key>index.html</Key>
...
```

Here, we can see a few key data points:

- The *Name* tag confirms our hypothesis that the subdomain is also the bucket name
- The contents are available and listed
- The first *Key* tag shows a *.bin* file that starts with "ami"

The *ami* file is interesting as it may refer to an Amazon Machine Images backup. Often, these backups are deployed to S3 buckets. You can download the file and inspect the contents but may not find much of interest; there is no clear file signature (*file* reports it as *data*), and I haven't found a way to extract the system contents from one of these files at the time of writing.

Still, if we can load the system, we can access it and inspect the contents. This may reveal key information: the web application's source code, hardcoded or stored credentials, and the underlying operating system.

### Restoring the AMI VM image

*Note: If you are doing this in TryHackMe, you can skip these steps unless you want to learn more about the underlying AWS service configuration. This is intended for people who are trying to access without the THM platform.*

The formal way to load an AMI image, even only with the purpose of extracting its contents, is to load it from an S3 bucket and import it as an EC2 instance. The bucket at *assets.bestcloudcompany.org* has solved the first step. Now let's approach the next.

Instead of setting up the whole environment for analysis, we could [export it to another format](https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html): OVA, VMDK, and a few others. This may prove useful if we only want to perform static analysis, or if we want to run the instance outside of AWS. However, we still need to import the AMI file, and since the export process requires another S3 bucket for output, that will take more time and space in the export bucket. In this case, it may be simpler to just set up a simple environment which permits SSH access, then delete those settings after we finish the lab.

With that in mind, our strategy is to connect to the EC2 instance's operating system. We can leverage SSH because it's fairly simple. With AWS, we will need to do the following steps:

- Restore the AMI image to an EC2 instance
- Generate an SSH keypair, which is required for [AWS SSH connections into EC2 instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html)
- Create an EC2 security group which allows for inbound and outbound SSH
- Launch the instance with these settings
- Connect using SSH and the newly-created private key

First, let's import the AMI VM image into an EC2 instance. Use the AMI key and the *assets.bestcloudcompany.org* bucket name, both of which are returned when you open the bucket in a browser. You can use an arbitrary name for the bucket.

```
~$ aws ec2 create-restore-image-task \
    --object-key ami-056a6742115906e8c.bin \
    --bucket assets.bestcloudcompany.org \
    --name s3labvm
```

If successful, it will return an identifier ID. Take note of it as you will need this later.

Next, create an SSH keypair. This will store your keypair in AWS and allow you to save it to a file. Set the local private key to read-execute only for the owner:

```
~$ aws ec2 create-key-pair \
     --key-name THMLabKeys \
     --query "KeyMaterial" \
     --output text > ~/.ssh/bestkeys.pem && \
   chmod 600 ~/.ssh/bestkeys.pem
```

Although you can use any *key-name*, take note of it as you will need it when launching the instance.

Next, create a new EC2 Security Group which permits SSH access. You can do so using the AWS web console or the command line. 

Since this is closer to a prototype than a full-on application, we only need to allow SSH. (Remember to delete this group later if you don't need it after the lab.) The end result will create a group that looks like this:

```
~$ aws ec2 describe-security-groups --profile default
{
    "SecurityGroups": [
        ...
        {
            "Description": "Allows SSH",
            "GroupName": "allowSSH",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "ToPort": 22,
                    "UserIdGroupPairs": []
                }
            ],
            "OwnerId": "...",
            "GroupId": "sg-...",
            "IpPermissionsEgress": [
                {
                    "FromPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "ToPort": 22,
                    "UserIdGroupPairs": []
                }
            ],
            "VpcId": "vpc-..."
        }
    ]
}
```

Take note of the *GroupId* value, which begins with "sg-", as you will need it when launching the instance. (In this screenshot, its full value is redacted, but yours will be a small hex string.)

Now, launch the instance, using the configuration values you got from previous steps:

```
~$ aws ec2 run-instances \
    --image-id ami-... \
    --instance-type t3a.micro \
    --key-name THMLabKeys \
    --security-group-id sg-...
```

Copy the *InstanceId*.

It will take a minute for the instance to spin up. You can check it with:

```
~$ aws ec2 describe-instance-status --instance-id i-...
```

The instance will have a *Status* of "initializing" until it's ready. Once ready, you can find the Public IP address using the `ec2:DescribeInstances` API call along with the instance ID and a query:

```
~$ aws ec2 describe-instances \
    --instance-id i-02f05991f4a149991 \
    --query 'Reservations[*].Instances[*].PublicIpAddress'
```

Once you have the public IP address, you can connect with SSH and your new keypair. We don't yet know if any users exist on this system; but we do know that SSH by default will permit root access. Let's try this user first:

```
~$ ssh -i ~/.ssh/bestkeys.pem root@<publicIpAddress>
```

The login attempt fails with a message to try the *bitnami* user instead of *root*. Modify that SSH command to use `bitnami@<publicIpAddress>`. Login is successful.

Upon login, you can poke around at the environment. This is a Debian-based Linux system, so feel free to leverage any shell commands to find anything of interest. My searching led to a few interesting findings:

- A file in the *bitnami* user's home which contains credentials. These credentials are, according to the contents, able to be used for different applications or databases.
- An HTTP server running on localhost. You can test this with *curl*, but the content isn't easy to read in the shell. To help with this, you could exfiltrate the file (using *scp*) to your host system for inspection. I found it easier just to install the *w3m* console-based web browser, then open the homepage. 

Either way, you'll notice that the localhost-ed site is nearly identical to the one at *bestcloudcompany.org*. We can infer that we might be using a clone of that production site. As further testing, we can prove that *localhost/wp-login.php* exists.

Using the credentials from the file in the home directory, logging in to the *localhost* site will succeed, sort of. (It gives a message about changing some administrator settings, but the login itself succeeded; if the credentials were invalid, this would have prompted us to log in again.) Regardless, if this really is a clone of the site, then maybe there's some credential reuse with both applications.

Go to *https://bestcloudcompany.org/wp-login.php* and try the credentials. Login is successful (womp, womp). The flag is in the user's profile description, although it doesn't use any indicators that it is in fact the flag.

# Recommendations

## Root cause analysis

The application overall suffers from a few problems, which we can align with the CWE Top 25:

- **Improper Authorization (CWE-862)**. Once we identified the S3 bucket's name, we could view everything within the bucket, including the application server backup, which contains sensitive and useful information.
- **Improper Authentication (CWE-287)**. The backup server's *bitnami* account can log in without a password. Since we didn't observe port 22 open on the production application, the developers may have believed that this is a non-issue, especially since AWS handles the SSH key management. In this case, the backup led to near-direct system access. Further, we might argue that the WordPress application should enforce multifactor authentication.
- **Use of Hard-Coded Credentials (CWE-798)**. In this case, the *bitnami* account contains the hardcoded credentials for a web-facing account. This might also be an example of "password reuse" which is still a major problem with many organizations and end-users.

## Mitigations

To prevent such attacks in the future, the organization might take the following measures.

- Apply a restrictive policy to S3 buckets. At the bare minimum, limit resources to only valid IAM principals within the organization. Ideally, someting like backups will be accessible only to a subset of members in the organization who work with system backup and restore.
- Separation of duties. Put backups into a separate, very restrictive bucket to avoid leakage to the public web. If a bucket is used for backups and web content (it shouldn't), consider creating a folder within the bucket and apply robust IAM policies to that folder and its contents.
- Leverage multifactor authentication. This prevents anyone with the username and password from gaining direct access to the account. In this case, it would have prevented us from getting the flag.
- Use unique passwords and avoid password reuse. Where possible, leverage a password wallet and lock down that wallet's access as appropriate.
- Remove hardcoded secrets. Although this usually applies to content returned to the user, in this case, we still got the credentials. If the application were vulnerable to command injection, it might be possible to extract them from the public internet, targeting the same file and dumping the file contents.