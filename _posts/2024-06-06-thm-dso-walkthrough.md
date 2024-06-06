---
layout: post
title: TryHackMe DevSecOps CTF walkthrough
date: 2024-02-18
---

# Overview of "Mother's Secrets"

This write-up was a black-box web application pentest. It is an unguided challenge and therefore resembles a "real" CTF. This writeup covers my own methodology, not just for finding the flags, but for testing the system as though this were a real engagement. 

Much of the real content is redacted or not included, as that would take the fun out of doing the challenge yourself. You are encouraged to use this as a guide to develop your approach, not as a cheat-sheet for the answers. (Incidentally, as you will see later, you can find all of the referenced file content online, available to the public, even without a THM subscription.)

Also, shoutout to the *Alien* theme and references throughout this challenge.

Without even reading the challenge description, keep in mind that this is a *DevSecOps* challenge. As you build a threat model of this application, keep in mind the attack surface:

- Secrets management (or lack thereof)
- Source-code management 
- Build and deploy configuration
- System environment configuration
- Application stack and configuration
- Insecure coding practices
- Identity and Access Management

Right off the bat, the last two will stand out in the "task files," which represent either a gray-box assessment, or an instance of leaked source code.

# Methodology

First, download the "task files," which contain source code for the application. This is a single flat file which contains code for two routes: `yaml.js` and `nostromo.js`.

First, inspect `yaml.js`:
- The *isYaml* arrow function only performs validation on the suffix of a given filename (ends with `.yaml`). In the real world, this would not be considered a "robust" solution for file validation. However, we will see later that this is a non-issue for our goals as an attacker.
- The route at `/` accepts a POST request with a JSON object containing a property called `file_path`. It validates whether the file ends with `.yaml` and then validates whether the file exists. In short, if you provide a real YAML file path, the contents of that file are returned. 
- The `file_path` string is unsafely inserted into `./public/${file_path}`. This can enable path traversal by the time it reaches the call to *fs.readFile*. Informationally, take note that this will target a folder called *public/* which exists in the same directory as `yaml.js`.
- Note that *fs.readFile* will return the contents of a file only. It will not return a directory listing. If the file does not exist, it will raise the error condition in the callback.
- Finally, there is an interesting import of `../websocket.js`. The business logic here seems trivial, but the import itself is of interest.

Now, inspect `nostromo.js`:
- The POST-based `/nostromo` route is nearly identical in behavior to the `/yaml` route seen earlier. There are two major differences, however: no filename validation, and logic that sets the global `isNostromoAuthenticate` variable to *true*. In short, if you give this route the path to *any* filename that exists, it will return the contents of that file unconditionally.
- Likewise `/nostromo/mother` POST route is nearly identical to the `/nostromo` route, but with two major differences. The first is that, in order to return the contents, two global variables must be *true*: `isNostromoAuthenticate` and `isYamlAuthenticate`. (The task file `yaml.js` does not include logic for `isYamlAuthenticate`, so it's possible that some or all of the source code is outdated.) The second major difference is that it reads files from a path called *mother/*, which is important to note as we build an understanding of the underlying structure.
- This imports `./yaml.js` from the same directory. In the application, we could expect both files to exist in the same place, although it is not yet clear what the folder is named.
- This also imports code from `../websocket.js`. Note that, in both routes' code, this exists one directory up.
- Finally, the commented-out import statement implies a folder at `../../mothers_secret_challenge`, which contains a file called `../websocket.js`. If you follow the relative paths, you'll notice that this could be the name of the project folder, as the location of `websocket.js` matches with this path.

Based on static analysis, we can infer the following:
- The project is likely based on NodeJS.
- A rough outline of the project structure is evident.
- The `/nostromo` route is the easiest to attack in order to achieve path traversal, and may prove the most valuable.
- The `/yaml` route can be exploited only if we know the location of a YAML file on the system.
- The `/nostromo/mother` route can be exploited only after `/yaml` and `/nostromo` are successfully executed.

We also have a rough outline of the project structure:

```
mothers_secret_challenge/
- websocket.js
- <folder>/
	- yaml.js
	- nostromo.js
	- public/
	- mother/
```

And some relevant technologies:

- [js-yaml](https://www.npmjs.com/package/js-yaml): Using *yaml.load* to load a [YAML file](https://snyk.io/advisor/npm-package/js-yaml/functions/js-yaml.load)
- [express](https://www.npmjs.com/package/express): Using *Router.post* for [POST-based routes](https://expressjs.com/en/guide/routing.html)
- [fs](https://nodejs.org/api/fs.html): Using *fs.readFile* to [read the contents of any file](https://nodejs.org/dist/latest-v6.x/docs/api/fs.html#fs_fs_readfile_file_options_callback)

With this in mind, let's visit the site at `http://IP_ADDRESS`. The home page is a single HTML file, which imports some JS files. Informationally, we will note the presence of `index.min.js`, but will safe static analysis for later because minified JS is a pain to read.

Aside from that, the frontend functionality is pretty limited. You can use the UP and DOWN arrows on your keyboard to navigate to different text panels. At this stage, the content does not reveal much, so we can save this for later.

Let's try to understand the API. The frontend does not reveal anything about where the routes exist, so you will need to test the route names with some [common API naming conventions](https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d). In this case, here are the locations:
- `http://IP_ADDRESS/yaml`
- `http://IP_ADDRESS/api/nostromo`
- `http://IP_ADDRESS/api/nostromo/mother`

Make sure you are using POST requests to access these. Otherwise, you will get a generic message about the "wrong route."

Earlier, we determined that `/nostromo` is the most exploitable route. First, try to exploit the Path Traversal vulnerability identified during static analysis. Let's try to fetch the contents of `../nostromo.js` because we know where this file lives: one directory above the *public/* folder: 

```
POST /nostromo HTTP/1.1
Host: http://IP_ADDRESS
Content-Type: application/json
...

{
  "file_path": "../nostromo.js"
}
```

The contents of this file, which we observed from the task file, is returned. We can infer two things here: that path traversal is achievable, and that file contents are returned as-is.

Next, let's also see if some common NodeJS artifacts exist. Try to return the `package.json`:

```
POST /nostromo HTTP/1.1
Host: http://IP_ADDRESS
Content-Type: application/json
...

{
  "file_path": "../package.json"
}
```

This returns the following:

```
{
  "name": "mother-secret",
  "version": "1.0.0",
  "description": "",
  "main": "server.js",
  "type": "module",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "compression": "^1.7.4",
    "express": "^4.18.2",
    "js-yaml": "^4.1.0",
    "nodemon": "^2.0.22",
    "socket.io": "^4.7.0"
  }
}
```

The contents confirm that the project is in fact NodeJS based. We can also see the imports from the task files in this package structure. 

Based on the *scripts*, it looks like the main logic lives in `server.js`. Let's inspect that file:

```
POST /nostromo HTTP/1.1
Host: http://IP_ADDRESS
Content-Type: application/json
...

{
  "file_path": "../server.json"
}
```

The contents:

```js
import express from "express";
import { fileURLToPath } from "url";
import compression from "compression";
import path, { dirname } from "path";
// import {routeNostromo} from "./routes/nostromo.js";
import routeNostromo from "./routes/nostromo.js";

import routeYaml from "./routes/yaml.js";
import http from "http";
import { attachWebSocket } from "./websocket.js";

const app = express();
const server = http.createServer(app);

export const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);

app.use(express.static(`${__dirname}/public/`));
app.use(express.json({ limit: "10kb" }));
app.use(compression());

// route middleware
app.get("/", (req, res) => {
  const filePath = path.join(__dirname, "views", "index.html");
  res.sendFile(filePath);
});
```

In itself, this reveals new information about the package structure:
- A folder called *views*, which contains `index.html`, the frontend application
- Since `index.html` imports `index.min.js` from the same directory, we can also infer that it too lives in *views/*
- `nostromo.js` and `yaml.js` both live in a folder called *routes*
- `websocket.js` lives in the top-level directory, alongside `package.json` and the major folders in use

Let's update our package structure map:

```
mothers_secret_challenge/
- routes/
	- nostromo.js
	- yaml.js
- websocket.js
- views/
	- index.html
	- index.min.js
- public/
	- ?
- mother/
	- ?
- package.json
```

At this point, you can also exploit path traversal to probe for information about the underlying filesystem:

- `../../../../etc/passwd` proves that we are on a Linux or Unix-like system, and reveals a few interesting artifacts. First, the existence of the `ec2-instance-connect` user implies that the server is an AWS EC2 instance. Second, the existence of the `ubuntu` user implies that this is an Ubuntu instance. Finally, the `www-data` user's home path of `/var/www` implies that our project lives somewhere in */var/www/*, a hunch that is reinforced by the minimum levels of directories needed to traverse to */etc/passwd* from the `/nostromo` route. So, this Node project likely exists at `/var/www/mothers_secret_challenge`, a common deployment pattern in Linux-based systems.
- The Ubuntu and Root users both have an `authorized_hosts` file, which implies that the capability to SSH into this box is feasible. (This is also revealed by a quick Nmap scan against the IP address.) However, no private SSH keys exist in common locations, so the capability to SSH into them is limited. Further, if you try to ssh in using the `ubuntu` user, you are denied with a public-key error, which implies that password-based authentication is disabled. Although SSH would be an easy way to pivot around the system, it may prove infeasible for this challenge.
- Because this is an EC2 instance, we can speculate that at least one YAML configuration file exists, which we can then use in the `/yaml` route to set `isYamlAuthenticated` to *true*. The hunch here is predicated by the fact that [EC2 cloud-init files](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#user-data-cloud-init) are often written in YAML format, and likely with a `.yaml` extension. In this system, inspecting `../../../../var/log/cloud-init.log` at line 361 will reveal the existence of `/etc/netplan/50-cloud-init.yaml`, whose relative path to *routes/* can be used in the `/yaml` route to authenticate.

If you follow the methodology thus far, you will successfully authenticate to `/nostromo/mother`, where you will need to dig for the secret file. The instructions imply the existence of `secret.txt`, and it may be worth checking that file at this time. (This is actually what I did the first time, and got mother's secrets before the other flags.)

However, since this seems like a poorly deployed Node package, it is also worth looking for other components that are commonly used with application projects.

- `Dockerfile` and `docker-compose.yml`, [Docker configurations](https://forums.docker.com/t/docker-compose-yml-or-dockerfile/133015), which may reveal build information and hardcoded secrets
- `.env` file, which [contains environment variables](https://nodejs.org/en/learn/command-line/how-to-read-environment-variables-from-nodejs) and may include hardcoded secrets
- `.git` folder and `.gitignore`, [artifacts from the Git version-control system](https://www.git-scm.com/docs/gitrepository-layout), which may reveal the existence of specific files in the project

These configurations often exist in the top-level directory of a project, so try to enumerate them one path up from *routes/*:

- `../.env.json`: *Error*
- `../Dockerfile`: *Error*
- `../.gitignore`: *Found!*

Since `.gitignore` is found, we can try to enumerate the contents of `.git` to learn more about the contents of the project. The only *potential* caveat is that, if these contents were not committed to Git, they will not appear in the `.git` artifacts. However, since this is a DevSecOps path, it is reasonable to speculate whether VCS triggered the build and deploy process; if so, the Git contents should reveal everything in the project.

The Git project structure is fairly predictable, and you are welcome to leverage the `/nostromo` route to pick any of them. For discovery purposes, two files are of particular interest:

- `.git/config`, a flat text file which includes metadata about the project
- `.git/index`, a binary file which contains strings, notably the paths to files in the project

Let's try to inspect the config file:

```
POST /nostromo HTTP/1.1
Host: http://IP_ADDRESS
Content-Type: application/json
...

{
  "file_path": "../.git/config"
}
```

The contents return, which imply that Git VCS is in use:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 276
ETag: W/"114-l3m2M+q7EwbIe2cuUUG/ULGbdA8"
Vary: Accept-Encoding
Date: Wed, 05 Jun 2024 20:04:56 GMT
Connection: close

[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/melmols/mothers_secret_challenge.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

At this point, I need to stop and make two major call-outs:
- Because `config` exists, it is reasonable to continue your black-box assessment by analyzing the `index` file. We will do this in a moment. However...
- If you inspect the URL, you should notice the cleartext path to a Git repository, https://github.com/melmols/mothers_secret_challenge.git

Remove the `.git` suffix from that URL and open it in your browser. The entire project is hosted on a public Github repository. At this point, you can complete the entire CTF by inspecting those files, as all the secrets exist there in clear text.

This is not a "normal" find for a CTF. However, this is a *DevSecOps learning path*; likely, the author of this challenge wants you to understand the importance of hardening your entire CI/CD, including *access to the entire repository*, *especially* when that repository contains hardcoded secrets (flags).

*Note: The user `melmols`, who maintains this repository, also appears in /home/ubuntu/.ssh/authorized_hosts. Based on previous challenges in this learning path, it is possible that they used SSH to deploy the application to this instance.*

You are welcome, and perhaps encouraged, to inspect this repository inside and out, as it may will certainly help you complete the CTF more quickly. However, I feel like this is taking the easy way out, so I will continue with testing the system as a black-grey box.

Anyway, let's pretend that the devs have secured the project repository, but deployed the `.git` folder. This is not a good practice. To demonstrate why, lest's talk about the `index` file.

From the [Git docs](https://git-scm.com/docs/index-format), you can learn all about the structure of this binary file. Of importance, let's review the Index Entries:

> An index entry typically represents a file.

To inspect the *index* file, you could use something like [*git cat-file*](https://www.git-scm.com/docs/git-cat-file). However, this would only work if we had access to the source repository (we're still pretending that we don't), or if command injection/shell access were achieveable on the server. Since neither of these conditions are true, we could leverage *strings* to get the text content, then filter it as needed with *grep*.

To understand the approach here, examine the following shell commands and outputs. In this example, we create an empty repo with two commits. Each commit adds a different file with a `.yaml` extension. Afterwards, we can dump all strings from the `index` binary, and optionally filter by `.yaml` patterns:

```
# Create a test repo.
$ mkdir git-test
$ cd git-test
$ git init
Initialized empty Git repository in /.../git-test/.git/

# Create a dummy YAML file and commit it.
$ touch file-a.yaml
$ git add . 
$ git commit -m "initial commit"
[main (root-commit) b037146] initial commit
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 file-a.yaml
 
# Create another file and commit that too.
# Git HEAD will now point to this commit.
$ touch file-b.yaml
$ git add .
$ git commit -m "added a file"
[main 8a56a6d] added a file
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 file-b.yaml
 
# View the names of YAML files from this output.
$ strings .git/index | grep '.yaml'
file-a.yaml
file-b.yaml
```

As you can see, in a black-box engagement, this may prove a feasible way to achieve file enumeration from a simple path-traversal vulnerability. The Git specification makes no claims that entires should be encrypted. So, it is reasonable to assume that the secrets appear in cleartext.

As noted earlier, you can use `/nostromo` to get the contents of any file on the system. But I'm still interested in why the `/yaml` functionality exists, especially since the "Alien Loaders" description calls out its importance. To me, this implies that there is a YAML file in the project structure; and we're going to use the `index` file contents to prove this one way or another.

First, fetch the file:

```
curl -X POST \
	-H "Content-Type: application/json" \
	-H "Accept: application/octet-stream" \
	-d '{"file_path": "../.git/index"}' \
	-o index.bin \
	http://10.10.120.111/api/nostromo
```

Then, inspect the contents for `.yaml` files:

```
strings index.bin | grep '.yaml'
...
public/100375.yaml
...
```

Indeed, this matches the same "control code" given in the CTF description. 

Now, let's try to enumerate `.txt` files:

```
strings index.bin | grep '.yaml'
...
mother/secret.txt
...
public/0rd3rXXX.txt
...
```

Using this enumeration, we have revealed the contents of the following interesting files:

- *public/100375.yaml*, which contains a reference to 0rd3rXXX.txt, and implies that the order number is XXX (redacted)
- *public/0rd3rXXX.txt*, which contains the "Nostromo route" flag
- *mother/secret.txt*, which contains a reference to */opt/m0th3r*, the location of the "Mother's secret" flag

By this point, we have four of the six flags, and have all but exhausted the server-side attack paths given the path-traversal vulnerability. For the final two, let's inspect the client. As noted, the core frontend logic exists in *index.min.js*.

When testing minified JavaScript, it is always a good practice to use a "beautifier" or "unminifier" tool. These tools will not defeat all of the obfuscation or mangling techniques, but it will lay out the code in a way that's easier to read and inspect.

With the unminified JS, try to identify key labels, such as variable or function names. Keeping the frontend behavior in mind, try to look for things that could reveal or authenticate the "hidden" content.

In this case, the following labels should stand out:

- *authYaml* and *authNostromo*, two variables which are initialized to *false*
- yamlSocket and nostromoSocket, websocket instances which interact with `/yaml` and `/nostromo` websocket routes
- *authWebSocket*, a function which uses these websockets and updates their "authentication" states programmatically, but reverts each *auth* variable to *false* in such a way that both variables are never *true* at the same time
- *modifyData*, a function that executes only when *authYaml* and *authNostromo* are both *true* at the same time

If you inspect the *modifyData* arrow function, notice the references to DOM manipulation (*querySelector*). This may control the state of hidden files in the client-side application.

Before probing too far, keep investigating the JS. Notice the massive array defined at `_0x491022`. You'll notice, among other things, the entire frontend text content, along with some Base64 encoded data, one of which decodes the client-side flag. The scientist's name is also there, and it should stand out if you watched the first *Alien*.

Before making assumptions, though, let's go back to the authentication logic. *modifyData* is defined in the global scope. It is callable without any arguments or prerequisite conditions. This makes the need to manage *authYaml* and *authNostromo* moot, and therefore represents another case of broken access control. It also means that we could execute this in the console and it should execute successfully.

In a real engagement, you should be careful about how you report this issue. Executing script in the console is not, for example, a Cross-site Scripting finding. The root issue here is not the code, but rather, the *hardcoded secrets* in the client code. This attack will already prove what we learned from the array at `_0x491022`: that, likely, *modifyData* just reveals the cleartext data stored here. 

In any case, open the Dev Tools and execute `modifyData()`. The HTML code now "reveals" the flag and scientist's name. It does so by taking values from that array and printing them to the console.

# Assessment

Overall, this report should focus on the following vulnerable coding patterns:

- Hardcoded secrets in the web and source files
- Lack of identity controls (Authentication), which is necessarily a prerequisite for access control (Authorization)
- Injection attacks due to unsanitized input, which allows an attacker to traverse files on the system
- Excessive privileges in the deployed web application, which enables an attacker to traverse files in locations like */etc*, and even in the root user's folder
- Nonexistent access controls for the source repository, which enables an attacker to steal the entire source code
- Deployment of excessive configuration files, which enable an attacker to learn more about the project by merely reading those files

Clearly, the frontend and backend developers mistake the secrecy of their business workflows as a proof of identity. They would benefit from hardening their CI/CD process, from using a SAST and Secrets scanner, and from implementing identity and access management.