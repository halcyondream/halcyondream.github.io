---
layout: post
title: Deep Dive Into AI Development for Security Practitioners
date: 2026-07-27
---

This section was originally part of my review of some good AI reads. I forked it to a new post because the content was, well, the size of a new blog post by the end. Each section here is a deep-dive based on questions I had after going through the books.

From personal experience, "an agent that reports on threat intel" seems to be the "hello world!" of Cybersecurity AI education. There's nothing wrong with this at all. This post focuses on several AI use cases, but the onus is on Offensive Security generally and Application Security in particular. My hope is that security practitioners who are unfamiliar with the nuts-and-bolts of AI development can take away new insights that they can apply to their own disciplines.

Brief overview of all sections:

- **RAG pipeline to identify relevant CWEs for vulnerability root-cause analysis**. Security practitioners who want to leverage vector databases' semantic search capabilities in LLM steps or agents can extend this to other types of signals, like CTI and threat reports.
- **A long discussion of Instructor, AI APIs, and agents**. This walks through how Instructor leverages the LLM provider's underlying code and web APIs, the limitations of the native code APIs, and guidance for choosing when to implement a formal agent (from a library; PydanticAI agents are considered here). Security practitioners who rely only on high-code agent workflows should consider these factors if LLM steps are already performing agent-like behaviors.
- **Consierations for offensive security agent tools and MCP**. Security practitioners should consider best practices for context window management, tools that reinforce the best practices of their own domain for the agent to consume, and when MCP becomes a better solution for advanced, standalone, framework-and-platform-agnostic agent clients.

## RAG lookup for Common Weakness Enumeration

An example workflow that I developed from this was a CWE classifier. It worked with smaller models, such as `gpt-oss-20b` and `mistral-small:24b`. (I had mixed results from smaller models, like `mistral-nemo:20b` and `llama3.2:7b`, which are more commonly used in lower-end commercial graphics cards.)

There are three primary steps in this:

1. Flatten CWE's XML (from downloads) into JSON
2. Load the CWE data from the transformed JSON into a Chroma vector DB
3. Expose an agent or model one-shot workflow to the vector DB to map new vulnerabilities to candidate CWEs

Key CWE properties are loaded into the database. Searchable fields are placed as the text content to enable semantic searching. Optional metadata is also provided:

```python
for doc_idx, cwe_file in enumerate(files):
    with open(os.path.join(target_folder, cwe_file)) as f:
        data = json.load(f)
    cwe_id = data["id"]
    cwe_name = data["name"]
    cwe_abstraction = data["abstraction"]
    cwe_mapping = data["mapping"]
    cwe_md = Path(os.path.join(md_folder, f"cwe-{cwe_id}.md")).read_text()
    
    # Restructure keyword lists as a cleartext string
    metadata_join = lambda array: ' | '.join(array)
    cwe_categories = data["categories"]
    cwe_violations = data["violations"]
    cwe_keywords = get_keywords(data)

    chunks = splitter.split_text(cwe_md)

    for chunk_idx, chunk in enumerate(chunks):
        collection.add(
            documents=chunk,
            ids=f"cwe_{doc_idx+1}_{chunk_idx+1}",
            metadatas={
                "cwe_id": cwe_id,
                "name": cwe_name,
                "categories": cwe_categories,
                "violations": cwe_violations,
                "keywords": cwe_keywords,
                "abstraction": cwe_abstraction,
                "mapping": cwe_mapping
            }
        )
```

An example of the query step (with adjustable parameters commented out):

```python
results = collection.query(
    query_texts=[question],
    n_results=n_results,
    where={
        "$and": [
            {"mapping": "Allowed"},
            {"abstraction": {"$ne": "class"}},
        ]
    },
)
```

Then, the results are given to an LLM one-shot for analysis. Instructor allows you to spit out a report in a predictable, streamlined format. Pydantic's base models enforce that schema:

```python
from pydantic import BaseModel, Field
import instructor
from dotenv import load_dotenv
import os

load_dotenv()


class CweResultsModel(BaseModel):
    top_cwe: str = Field(description="The most relevant CWE ID")
    secondary_cwe_id: str = Field(description="A runner-up CWE ID")


client = instructor.from_provider(
    "openai/gpt-4o", # Could also be an .env setting.
    api_key=os.environ.get("API_KEY"),
    mode=instructor.Mode.JSON,
)

# Query the vector database.
cwes = collection.query(
    query_texts=[question],
    n_results=n_results,
    where={
        "$and": [
            {"mapping": "Allowed"},
            {"abstraction": {"$ne": "class"}},
        ]
    },
)

# Keep all CWE document matches.
cwes = results.get("documents")[0]

system_prompt = "Identify the top two CWEs from <cwes>"
user_prompt = f"<CWEs>{cwes}</CWEs>"

# Offload to an LLM to evaluate the most relevant matches.
response, completion = client.create_with_completion(
    model=model,
    messages=[
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ],
    temperature=0.3,
    response_model=CweResultsModel,
)

print(f"Top CWE: {response.top_cwe}\nSecondary CWE: {response.secondary_cwe}")
```

You can leverage the semantic search for vulnerability triage like:

> Reflected cross-site scripting identified in the frontend SPA code

The output would be something like:

```
Top CWE: CWE-79
Secondary CWE: CWE-352
```

If you need to process the results as JSON, you can leverage the base model's `model_dump_json()` method.

```python
import json
...

cwe_json = json.loads(response.model_dump_json)

print(json.dumps(cwe_json, indent=2))
```

You can also add an LLM step, also using instructor, to transform a large input into a RAG-appropriate query, then query the vector database using that string, or return an error like "Too ambiguous" to the user. Finally, because vector DBs are also probability machines, you could use any confidence score metrics to further refine the RAG search.

For simplicity, this workflow uses a local ChromaDB instance. But as with LLM providers, there are lots of cloud providers for vector databases out there, including S3 vectors and, well, Chroma cloud. This implies additional cost but is more production ready than a local prototype deployment. 

N8N workflows also allow for this type of thing. My RAG pipeline was trivially usable from a local, sandboxed N8N instance using an AI Agent step and a minimal frontend, plus some additional formatting. This effectively does the same thing but with a user interface.



## Offensive Security Agent Tools

For my purposes, I took an interest in the summarizing page content approach. The MCP server exposes a Playwright webdriver but in a way that is suited for web application testing. In the book, the tool that returns the page body is truncates the page contents to 2,000 characters to avoid flooding the context window. 

While this may seem reasonable for a simple target, it becomes pretty infeasible when you are designing a more robust reconnaissance framework. Single-page application frameworks will fetch one page and any number of JS files (chunks), which can be megabytes in size. If you want, instead of using the book's MCP implementation, try using the `@playwright/mcp@latest` package directly in your agent; a simple recon task will burn out within a minute or two, because you've flooded the context window.

As the context window grows in size, the agent's ability to function well will degrade drastically, or it will stop the agent thinking entirely.

> You'll know you hit the limit because the provider will return a message like, "Cannot send a message of 10,000,000,000 tokens for a context size of 200,000k tokens."

The question of "how do you find that balance?" is not a straightforward one. But you can experiment with different, custom tools to find the grain. Here are some tool examples that you can try to implement:

- `save_url_content(url: str) -> string`: The tool saves a URL's content to a file. The file can be ephemeral or long-lived. Alternatively, leverage a database (like MongoDB) to save content.
- `get_labels(file_path: str|None, url: str|None) -> list[string]`: The tool fetches all alphabetic strings of four or more characters found in a given file or URL. The agent analyzes the strings with respect to conversation history and tries to determine things like RBAC boundaries, sensitive actions, or ambiguous but hardcoded secrets that may have been missed by regex scanners. 
- `get_js_function(url: str|None, file: str|None) -> str`: The tool analyzes a JavaScript function from a URL or file path, parses the AST to find a function of that label/scope, and returns its definition. The agent can analyze that function for general behaviors, weaknesses, and initial exploit payloads.
- `get_regex_search(pattern: str, url: str|None, file: str|None) -> str`: Perform a regex search on a file or URL contents. You can invalidate the tool call if factors like ReDoS conditions were submitted.
- Any of these tools could truncate the output, or send the output to a `summarize(large_output: str) -> str` tool that performs an LLM (not agent) one-shot against all parts of the output until its semantic meaning is determined. This retains their meanings for your main agent while saving yourself from polluting your agent's context window.

The emergent pattern is that the tools control access control, payload sizes, and intermediary steps. We are anticipating a more-aware, more autonomous (and more expensive) Burp Suite.

Here, the agent's file access is assumed to be hardened or from some shared space, but you'll have to do that work. If you're using a desktop app, like Claude Desktop, use an STDIO MCP server, then build it out into an HTTPS one later.

MCP servers offer a decoupled exploit framework. Code frameworks like PydanticAI offer their own `@agent.tool` style wrappers that let you directly code your adjustments into the preferred agent. 

Here's an example of a FastMCP implementation of the regex search tool:

```python
from fastmcp import FastMCP
import re
import requests
from .utils import beautify_js

mcp = FastMCP("Web App Testing MCP Server")

@mcp.tool
def get_regex_search(pattern: str, url: str|None, file: str|None) -> list[str]|str:
	"""
	Use this to perform a regex search against a shared file or URL.
	You must submit either a file or URL.
	
	Args:
	pattern (str): The regex pattern to be used with Python's re module
	url (str|None): The URL whose contents you want to analyze
	file (str|None): The path to the shared file you want to analyze
	
	Returns:
	str: The results of the regex match, truncated to 2,000 characters
	"""
	content = ""
	if redos_condition(pattern):
		return "Error: Pattern contains a ReDoS condition, will not process."
	
	if file:
		with open(file) as f:
			content = f.read()
	elif url:
		resp = requests.get(url)
		if not resp.status_code != 200:
			return f"Page returned a {resp.status_code} response"
		content = resp.text
		if url.endswith("js"):
			content = beautify_js(content)
	matches = re.findall(pattern, content)
	return [m[:2000] for m in matches]
```

We define some corner cases and return exactly what we say in the docstring. The agent using this MCP server will use all of this to invoke the tool as needed.

Of note, I also define a nonexistent `beautify_js` function. This makes it easier to perform regex searches because more JavaScript content will exist on newlines. Among other things, this solves the problem of a single regex match returning one line with 5MB of data.

Now you can ask the agent questions like:

> "Find any indicators of different roles or access control boundaries from `http://foo.tld/chunk-abc123ef.js`"

For other text cases, like a markdown paragraph where one line contains a ton of data, you could use a markdown linter. For simpler cases, split the text and rejoin it with newlines, or do a line-by-line match. You get the idea.

Here's an identical implementation that uses PydanticAI's "plain tool" approach:

```python
from pydantic_ai import Agent

agent = Agent(model="openai:gpt-4o", instructions="Pwn the web app", ...)

@agent.tool_plain
def get_regex_search(pattern: str, url: str|None, file: str|None) -> str:
		# Same docstring and implementation here...
```

Some frameworks have other ways to define tools. For example, PydanticAI lets you pass its runtime context into its tools with the `@agent.tool` wrapper. You can use this to manage context or to spawn tightly controlled subagents:

```python
from pydantic_ai import Agent, RunContext

agent = Agent(model="openai:gpt-4o", instructions="Pwn the web app", ...)

@agent.tool
def get_regex_search(ctx: RunContext, pattern: str, url: str|None, file: str|None) -> str:
	# Same docstring...

	# Example corner case: Do not process if the context window has surpassed 
	# 50,000 tokens.
	if ctx.usage.tokens > 50_000:
		return "Not performing expensive regex operation"

	# Continue with same implementation...
```

In reality, your corner cases will be more tactical, but hopefully you get the idea.

The point is that tools can help target the problem you want the agent to solve, enforce a model-agnostic approach to your pentest, and substantially reduce cost.

The choice between a framework's tools versus a full-on MCP server depends entirely on your use case and the maturity of your solution. If you're prototyping, try a simple tool definition. Once you feel confident, deploy it as an MCP server.

With that in mind, an outstanding factor with testing agents is literal financial cost. Even simple agent runs can burn though tens or hundreds of thousands of tokens. This is especially frustrating when you're trying to get it to do what you want. Tools are a good way to narrow down the problem and get better results, so you can invest money in a solution that actually works.

Agents have lots of capabilites which were only surveyed here. You can extend them with skills and multiagent solutions. For example, PydanticAI offers a deep agent harness (file systems, tool overflow behaviors, etc.) and graph capabilities. These are not exclusive to PydanticAI, so you'll need to research your chosen framework to see what it can help you with; then you'll need to test how well it works, or if it works for your use case, which costs some money.

You can find new MCP servers all the time nowadays. Burp Suite, Metasploit, Kali Linux, and other well-known tools all have integrations. Their effectiveness is still very much TBD, and they all run the risk of the caveats previously discussed (namely, a large context window). But they're all worth a shot.

Finally, I end this by noting that there are some pentest-specific agent projects out there, including: GH05TCREW's PentestAgent and KeygraphHQ's Shannon. I have found that these highly specialized agents come with a lot of prebuilt features but burn an insane amount of money. They also have serious cost caveats, which is expected when you're rolling your own agent in code.

My personal opinion so far is that, if you want that kind of tool, figure out how to implement the tools/integrations with a competent desktop agent first. Then write the custom agent or logic.