# Goals

By the end of this walkthrough, we will:

- Understand CIDR notation
- Convert binary to decimal
- Determine a subnet mask from the CIDR subnet value
- Determine the Subnet ID, Broadcast IP, start and end IP addresses for a subnet

We cover two example IP addresses:

- 192.168.17.24/20
- 192.168.17.24/25

In the first example, the most significant value is the third decimal/octet from the Host IP. In the second example, the fourth decimal/octet is the most important. The *way* we find the subnet properties changes depending on which decimal/octet is the most important.

# IP and Subnet notation

CIDR notation looks like this, an IP and an integer between 0 and 32 (separated by a slash).

````
192.168.17.24/20
````

In this example:

- **Host**: `192.1618.17.24`. This is a specific IP on the network.
- **Subnet**: `20`. This means, "in binary, the first 20 digits out of 32 are 1's." The remaining digits are zeroes.

# The subnet value in CIDR format

Let's use the IP address `192.168.17.24/20` from the first part. We already establish that the subnet value is **20**. Here's how that looks in binary:

```
11111111 11111111 11110000 00000000
```

Again, the subnet value (20) is the number of leading ones. The remaining digits are zeroes.

Note that the first two octets (eight binary digits) are all one. Note also that the last octet is all zeroes.

This matters when you need to get the value of the subnet *mask*. The full subnet mask can help you find other properties of the network: network address/subnet ID, first and last host addresses, and broadcast ID, to name a few.

Note that the subnet mask is `255.255.240.0` in decimal. We get this value by converting it from the binary from noted here. In the next section, we will prove why.

# Binary and Decimal Conversions

To find the subnet properties, we need to know how to:

- convert binary to decimal
- convert decimal to binary

## Converting binary to decimal

To get the subnet properties, we first need a way to convert binary to a decimal form. This is crucial to get a subnet mask from its binary form. There is an "easy" and "hard" part to this, but they should become easier with practice.

### The harder part

In short, each digit in an octet refers to values in base 2: 128, 64, 32, 16, 8, 4, 2, 1 (from left to right). 

- An octet like `10000000` equals **128** because the first digit is 1, which corresponds to 128. 
- An octet like `10000001` equals **129** because the first bit = 128 and the last bit = 1, such that 128 + 1 = 129. 
- As a final example, in `01100010` = **98**, because the bits 64, 32, and 2 are set to 1, such that 64 + 32 + 2 = 98.

It could help to think of it with a table. Let's use the final example, `01100010` = 98.

| Decimal    | 128  | 64   | 32   | 16   | 8    | 4    | 2    | 1    |
| ---------- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| Binary bit | 0    | 1    | 1    | 0    | 0    | 0    | 1    | 0    |

The sum of the decimal value(s) in the top row is the . Spreading out the digits like this, you can clearly see which bit corresponds with each decimal. The sum is the decimal value.

As a final example, consider the third octet in the subnet mask, `11110000`. The bits for 128, 64, 32, and 16 are set. The sum of these is 128+64+32+16 = **240**.

## The easier part

With that in mind, let's consider two fringe cases: an octet of all ones, and an octet of all zeroes. These are very easy to identify.

- All ones = **255**. Think about why. If every bit is set, then the sum of all bits is just 128+64+32+16+8+4+2+1 = 255.
- All zeroes = **0**. Conversely, if *no bits* are set, then the sum of eight zeroes is just zero.

In the subnet mask example (previous section), note that the first two octets are all ones, and the final octet is all zeroes. 

## The subnet mask example

Using the previous two subsections, we can convert the binary subnet mask:

```
11111111 11111111 11110000 00000000
```

Converting to decimal values:

- `11111111` = 255
- `11111111` = 255
- `11110000` = 240
- `00000000` = 0

So, the subnet mask is `255.255.240.0`.

## Converting decimal to binary

This is the opposite of the previous section. Read it first. Before going any farther, keep in mind that the largest value you will work with in a subnet or IP is 255, and the lowest value is zero. This approach only works because of that fact. Also, this approach uses integer divisions; don't worry about decimals or fractions.

The approach is something like this:

- Divide the decimal number by the next-lowest bit decimal. Note its quotient (either 1 or 0) and modulus (remainder, integer).
- If the quotient is 1, mark a 1 is the corresponding bit location.
- Repeat this with the remainder and the next-lowest bit decimal with respect to the remainder.
- If the remainder skips any bit-decimal places, mark those spots as zeroes.
- Stop when the quotient is zero.

As an example, let's convert the value 240, since we already know what it looks like:

- 240 mod 128 = 112, 240/128 = 1
- 112 mod 64 = 48, 112/64 = 1
- 48 mod 32 = 16, 48/32 = 1
- 16 mod 16 = 0, 16 / 16 = 1
- 0 mod 8 = 0, 0/8 = 0 (done)

The first four bits are set, `11110000`.

### In Python...

```python 
DECIMALS = [
    128,
    64,
    32,
    16,
    8,
    4,
    2,
    1
]


def get_binary(n: int) -> str:
    """Get the binary representation of the decimal input."""
    
    binary = []
    m = n
    
    for d in DECIMALS:
        
        binary.append("1" if m//d else "0")
        m %= d
    
    return ''.join(binary)


print(get_binary(240))	# Prints `11110000` to the console.
```

# Subnet properties

Using this, we can identify the following:

- Number of hosts per subnet
- Subnet ID/Subnet IP/Network Address
- Broadcast IP
- Start and end host IPs

For this section, we are going to make our lives easier and use `192.168.17.24/20`. We show earlier how to get the subnet mask, which is `255.255.240.0`. We need ***both of these*** values to perform the following steps.

If you want to see what these values look like quickly, just use a Subnet calculator. If you want to cheat, this host IP/subnet is already loaded [here](https://www.calculator.net/ip-subnet-calculator.html?cclass=any&csubnet=20&cip=192.168.17.12&ctype=ipv4&printit=0&x=94&y=18) (along with more information). The following will explain how to get these values.

## Determining the Subnet IP

Think about the given Host IP and Subnet Mask as four decimal values separated by periods. Each value represents a binary octet. Now, think about each of these four numbers/octets in the Host IP "lining up" with those in the Subnet Mask. We can visualize this like:

| 192  | 168  | 17   | 24   |
| ---- | ---- | ---- | ---- |
| 255  | 255  | 240  | 0    |

With this in mind, we can get the subnet IP pretty easily:

- If a decimal lines up with a 255, keep that value. In this example, the numbers **192** and **168** line up with a 255. 
- if a decimal lines up with a zero, use the value **0** (disregard its host number). In this example, the **24** lines up with a zero. So, we ignore it in the subnet IP.

So far, we have the following parts of the Subnet IP:

````
192.168._ _ _.0
````

The third decimal/octet lines up with 240. This will require a bit more work.

First, get the binary representations of each number. Using the decimal-to-binary approach, we find that 17 is `00010001`. Using our notes from earlier, recall that 240 is `11110000`. 

Line up these two octets:

````
00010001
11110000
````

We use this to make a new octet, convert that to decimal, and use it in the Subnet IP.

If a bit is `1` in *both octets*, then that value persists into the new octet. In this example, the fourth octet is 1 in both. Recall from earlier that this value corresponds to 16. 

We can use a table to show this:

| Decimal | 128  | 64   | 32   | 16    | 8    | 4    | 2    | 1    |
| ------- | ---- | ---- | ---- | ----- | ---- | ---- | ---- | ---- |
| 17      | 0    | 0    | 0    | **1** | 0    | 0    | 0    | 1    |
| 240     | 1    | 1    | 1    | **1** | 0    | 0    | 0    | 0    |

So, the third decimal is just **16**.

The full subnet IP is thus:

```
192.168.16.0
```

## Determining the number of hosts per subnet

First, determine the number of ***host bits per subnet***. You can find this by using the CIDR subnet number. Recall that this value is between 0 and 32: the number of possible 1's in the subnet mask. Since the value can have a maximum of 32 1's, then subtract 32 from the CIDR subnet value.

In our case, 32 - 20 = **12** bits. 

Fun fact, this is the number of trailing zeroes in the subnet mask. (You can count them in the binary representation from earlier.)

With this number of host bits per subnet, we get the actual hosts per subnet by raising 2 to the power of b bits, and subtracting 2 from that product. (We subtract two because the Subnet IP and Broadcast IP are reserved values.)

For this subnet, 2^{12} - 2 = 4096.

So, this subnet can support up to **4096** hosts.

Note that this is the total number of hosts across all subnets. To get the broadcast ID for this subnet, we need to get the number of subnets.

## The number of subnets

To calculate the number of subnets, we need the number of bits borrowed (which are allowed for subnet/network creation, and are thus unavailable to hosts on this network). The bits borrowed from the host is the difference between 8 and the number of bits in the subnet mask's binary octet which is not all ones or all zeroes. In this example, the number is 240, which is `11110000`. So, there are four (4) borrowed bits.

To get the number of subnets, raise 2 to the power of borrowed-bits. In this case:

​	2^{4} = 16

So, this network has **16 subnets**.

## Start and End Host IPs

### Start IP

The **start IP** is just the Subnet IP's fourth decimal value (zero) plus one: in this case, `192.168.16.1`.

### End IP

The **end IP** is the start IP + number of hosts: so, 192.168.16.1 + 4096. Note that we will need to do a bit of work, as the third decimal place (16) increases. This third value in the end IP increases by the number of hosts divided by the number of subnets---minus one. (The "minus one" is an offset for the start IP of the next subnet). In this case:

​	(4096 / 16) - 1 = 15

Since this is the third decimal, the fourth decimal will end with 254. *(Recall the range of 256 = {0, ..., 255}, where the Subnet IP takes 0 and the Broadcast IP takes 255.)*

Thus, the end IP is `192.168.31.254`.

#### Note about how we got the End IP...

As a final note: we change the value of the third octet because it aligns with a non-zero subnet octet. In many cases, the fourth octet is changed in the same manner that we used for the third one here. If you want to see this, try this activity with values `/24` through `/32` instead.

## Determining the Broadcast IP

Finally, the Broadcast IP is the End IP's final octet + 1: `192.168.31.255`.

## tl;dr

| Name                    | Value                         |
| ----------------------- | ----------------------------- |
| IP Address:             | 192.168.17.12                 |
| Network Address:        | 192.168.16.0                  |
| Usable Host IP Range:   | 192.168.16.1 - 192.168.31.254 |
| Broadcast Address:      | 192.168.31.255                |
| Total Number of Hosts:  | 4,096                         |
| Number of Usable Hosts: | 4,094                         |
| Subnet Mask:            | 255.255.240.0                 |

## What if the subnet changes?

Say the subnet changes from 20 to 25. In this case, you will, unfortunately, have to repeat all of these steps to find the new values. Don't kill the messenger.

When this happens, the "borrowed bits" is just the difference between the original and new subnet value from the CIDR form. If we increase that value from 20 to 25, then there are 4 borrowed bits (25 - 20 = 5). The CIDR IP looks like:

```
192.168.17.24/25
```

Since we know there are 25 leading 1's, the subnet mask is 255.255.255.128. In this case, the subnet's fourth octet (10000000 or 128) is the one that will change. 

*Note: Anything between 24 and 32 is actually an easier subnet to work with. The previous section took a bit more work because we needed to get the number of subnets in order to calculate the number of hosts per subnet. In this section, we do not need this: we just use the hosts per subnet value and ignore the number of hosts per subnet.*

The Subnet IP/Network Address is based on the final decimal/octet. (The first three subnet values are 255. So, we retain 192, 168, and 17 in this subnet.) We prove that the fourth decimal in this address will just be zero (0).

```
00011000	# 24 from the Host IP.
10000000	# 128 from the Subnet Mask.
--------
00000000	# Subnet IP/Network Address
```

The Subnet IP/Network Address is **192.168.17.0**. This yields a start IP of **192.168.17.1**.

The number of hosts is 2^{32 - 5} = 2^{7} = **128**. So, the hosts per subnet is 128 - 2 = **126**. The end IP is just the subnet IP plus the hosts per subnet: 192.168.17.(0 + 126) = **192.168.17.126**.

Using the steps noted earlier, we can derive the [following subnet info](https://www.calculator.net/ip-subnet-calculator.html?cclass=any&csubnet=25&cip=192.168.17.12&ctype=ipv4&printit=0&x=75&y=37):

| Name                  | Value                         |
| --------------------- | ----------------------------- |
| Network Address:      | 192.168.17.0                  |
| Usable Host IP Range: | 192.168.17.1 - 192.168.17.126 |
| Broadcast Address:    | 192.168.17.127                |

***Note:** As explained earlier, we do not really need the number of subnets for this question. This is because the fourth decimal/octet updates, not the third one. So, we do not need to divide the total hosts (128) by this value. Still, we can use this value to show different IP ranges for this subnet. Note that the number of subnets are 2^{8 - (32 - 5)} = 2^{8 - 7} = 2^{1} = **2**. If we needed to show the the next subnet range (including Subnet and Broadcast IPs), we note that it just includes the next 128 hosts. Its range is `192.168.17.129 - 192.168.17.255`. Since there are only two subnets, we are done.*

