---
layout: post
title: How To Know When You're Actually Just Writing An Agent
date: 2026-07-29
---

In my journey of AI development, I've come across two patterns: LLM steps in deterministic workflows, and Agentic AI steps. It's hard to tell the difference when you're consuming a bunch of new information all at once. Given the speed at which many of these frameworks are evolving, it may serve you to ask: at what point are you actually writing an AI agent?

In the beginning, there were AI steps in procedural code and workflows. And this was fine until AI capabilities, like tools and multi-shot reasoning gates, started to evolve. This led to the formalization of agents, which perform many actions autonomously, and ultimately abstract the same layers you were using in the pure procedural approach.

This transition led to a lot of agent-like approaches in procedural code. The MCP project's own tutorial on writing MCP clients is a good example of this. Another example is GH05TCREW's PentestAgent, which functions as a CLI pentest agent, but doesn't use any "modern" agentic libraries. 

The difference between an LLM step and a workflow really lay with your intention, your need to control the agent steps, and your appetite for cost. Modern agentic code libraries try to find a harmony here. But you, the reader, have to pay the token bill, so it's worth your time to reflect on your goals and decide if your current approach is fine, or if it could (or should) be optimized by a new library.

What exactly is an agent? They tend to have three outstanding qualities:

- The agent is exposed to tools, which you define manually (code functions), or through transport protocols like MCP.
- One question can trigger any number of LLM rounds. You, the developer, have limited if any control over what happens during those rounds.
- Agents are provided different types of knowledge bases, namely: the system prompt; access to a vector database; skills, which are descriptive and code based; and so forth.

Unless you've been asleep for the past five years, you've probably heard of code-first agents, like Cursor and Codex. These applications perform these steps and many others. But the way it does so is abstracted from the user.

OpenAI's recent attack against HuggingFace also secretly was an agentic attack scenario. The agent was given a number of capabilities via the ExploitGym harness. The underlying LLMs leveraged those tools in order to escape the sandbox and attack HuggingFace. 

In short, the model didn't do that on its own. It needs tools and knowledge (and money). This is true of all agents, custom or prebuilt alike. 

Security engineers should remain well aware of this line. An LLM step has classic attack vectors like model poisoning, "prompt injection," and statistical analysis exploits. Agents inherit those problems and bring new ones to the table: arbitrary code execution, OS command execution, and denial-of-wallet, to name a few.

With that said, agents probably aren't going away any time soon.

In this walkthrough, I'll trace the development process from "this started out as one step" to "this is starting to look like an agent." We will consider the pros and cons of LLM steps and determine the point at which we are just implementing a controlled, code-heavy agent with extra steps. Cost will not be the focus but it will be considered along the way.

This guide considers three Python libraries to exemplify the major poitns:

- OpenAI: The provider's official code library
- Instructor: An LLM abstraction layer for structured text output
- PydanticAI: An "Agentic AI from scratch" code library

What all of these have in common is their use of Pydantic's schema (specifically, subclasses of the `BaseModel` type). Structured output is a good strategy to save money in tokens as it can limit the amount of data the LLM returns. 

The downside in all approaches is the developer's management (or mismanagement) of the context window. Tool definitions, skills, and schemas can quickly flood the token space and trigger lockouts or hallucinations. This guide does not delve deep into management strategies, but you should be aware of this when you're rolling your own LLM solutions, whether they're just one-shot steps or multi-round agents.

Finally, multi-agent patterns are starting to dominate the market. ClawdBot was a well-known security fiasco, but the core idea isn't going away. So long as agents persist in our environments, the overall findings and need for governance will prevail.

We'll start with a simple case, analyze how Instructor can make our lives easier, and end with an equivalent solution as a code agent.

## About Provider APIs

Before we get in the weeds, we need to understand that every AI code framework is secretly a wrapper that makes web calls to the provider's API. The term "provider" here is loosely defined as whatever serves the web API that your code solution ultimately consumes. For simplicity, I stick to OpenAI, but you can perform the same type of research against Ollama, Anthropic, and any others.

OpenAI currently showcases two major web APIs used to invoke their models:

- [**Responses API**](https://developers.openai.com/api/reference/python/resources/responses). This is OpenAI's recommended API for new projects. In their words, it represents their opinion on future development, and has an eye on agentic use cases while still supporting deterministic ones. For most use cases, it is identical to chat completions.
- **Chat Completions API**. This API has been around for years and is probably the best documented at this point. OpenAI still supports it, but discourage new projects from using it. It still works, but if you're doing a serious development task, prefer the Responses API.

> To make things a little more confusing, neither of these should be confused with the outdated "Completions API."

An example of the Responses API looks like the following:

```python
from openai import OpenAI

client = OpenAI()

response = client.responses.create(
    model="gpt-5.6",
    input=[
        {"role": "system", "content": "Extract the event information."},
        {
            "role": "user",
            "content": "Tell me a funny joke",
        },
    ]
)
```

For this small example, we can also use the Chat Completions API in an identical manner:

```python
response = client.chat.completions.create(
    model="gpt-5.6",
    input=[
        {"role": "system", "content": "Extract the event information."},
        {
            "role": "user",
            "content": "Tell me a funny joke",
        },
    ]
)
```

The `create` method is based on the API specification. It happens to exist in Responses and Chat Completions. It's the usage of `responses.create` versus `chat.completion.create` that changes.

Here's an equivalent Responses API call using `curl`:

```bash
curl https://api.openai.com/v1/responses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-5.4",
    "input": "Tell me a three sentence bedtime story about a unicorn."
  }'

```

And for the Chat Completions API:

```python
curl https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-5.4",
    "messages": [
      {
        "role": "developer",
        "content": "You are a helpful assistant."
      },
      {
        "role": "user",
        "content": "Hello!"
      }
    ]
  }'

```

In short, the Python code package is just a collection of convenience wrappers that make calls to the platform's API.

A final observation: the Responses API makes a request to the `/responses` path, and Chat Completions to `/chat/completions`. 

In a minute, we will see that both solutions also accept Pydantic schemas for structured output. We will explore, perhaps in too much depth, how each one uses the schema under the hood. But before we do that, I want to introduce a convenience library, Intstructor, that can handle structured output for *any* provider API, not just OpenAI.

Why use something like Instructor? The rationale is simple. If you change providers, it saves you from refactoring your codebase, or from implementing a catalog of custom wrappers.

If you must roll your own LLM client abstractions, look to Instructor as a way to approach the problem. Let's do that now.

## Analyzing Instructor's use of provider APIs

In the book review, I only superficially covered Instructor. Their developer documentation is rich and the project offers a lot of useful features. I'll cover some edge cases and deep dives that was left outside of the book's scope.

Under the hood, most of the Instructor providers secretsly use the provider's upstream code/web APIs. Let's explore two such APIs, the chat completions and the responses API, as they are used by OpenAI.

If you read the Chat Completions docs, you'll notice an absence of any explicit structured output parameters. Some practical sources on the web will say that you can handle it in the context window or by defining a tool that achieves the same goal. This approach is sane but produces ugly code.

For those reasons, the Responses API seems a little more attractive. This snippet is again from OpenAI's documentation:

```python
from openai import OpenAI
from pydantic import BaseModel

client = OpenAI()


class CalendarEvent(BaseModel):
    name: str
    date: str
    participants: list[str]


response = client.responses.parse(
    model="gpt-5.6",
    input=[
        {"role": "system", "content": "Extract the event information."},
        {
            "role": "user",
            "content": "Alice and Bob are going to a science fair on Friday.",
        },
    ],
    text_format=CalendarEvent,
)

event = response.output_parsed
```

If you read the [API Documentation](https://developers.openai.com/api/reference/python/resources/responses/methods/create), not just the developer docs, you'll notice that the Python examples will use `requests.create` and `requests.parse`. As we will see in a minute, these ultimately converge into an equivalent HTTP request structure to the `/requests` base path. For the sake of the walkthrough, just note that `requests.parse` is just a convenience wrapper for `requests.create` that simplifies structured output the "OpenAI way."

> Note: You can use the `requests.create`'s `text` argument to manually construct the schema. This is terrible to read, so I won't be doing it. We will see an equivalent result later.

The "Instructor way" to handle a request with structured output would look like this, a toy code example shamelessly copied-and-pasted from their own documentation. We'll call it `instblog.py`:

```python
import instructor
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


class Person(BaseModel):
    name: str
    age: int
    occupation: str


client = instructor.from_provider("openai/gpt-4o")

# Extract structured data from natural language
person = client.create(
    response_model=Person,
    messages=[
        {
          "role": "user", 
          "content": "Extract: John is a 30-year-old software engineer"
        }
    ],
)

print(person)  # Person(name='John', age=30, occupation='software engineer')
```

Instructor's client uses [different modes](https://python.useinstructor.com/modes-comparison/), which are available via the `mode` parameter in the `from_provider` function.

By default, clients use the `mode=instructor.Mode.TOOLS` under the hood. This converts each structured output to the provider's native tool format. Other options, like `instructor.Mode.JSON_SCHEMA` will make a best-effort attempt to leverage the provider API's native structured-text fields if those options are available. Later, we'll switch to the `instructor.Mode.RESPONSES_TOOLS` to support OpenAI's Responses API. For now, the default tool mode is fine.

The `create` method doesn't really tell us anything about the API in use. The Chat Completions API and Responses API both support a `create` operation. The first question we should ask is: does it matter which API it uses?

It might not surprise you to learn that the instructor `mode` parameter determines one versus the other. We will explore this in a minute. For now, pretend you don't know; if you were auditing a new library, and the library's maintainers were unclear, you would have to walk through these steps anyway.

For "best practices," this may be something you need to explore. For security, you might consider any differences between access control/authorization, validation, etc. I will avoid an in-depth security audit in favor of tracing behaviors.

In short, let's assume we must perform a deep analysis.

If you run this script in a debugger, set a breakpoint at `client.create`, and step into it. You can begin tracing the point at which Instructor actually crosses over into the OpenAI package:

```
# Run command in the Python debugger...
import traceback
for frame in traceback.extract_stack():
    _module = frame.filename
    if "debugpy" in _module or "pydevd" in _module or "runpy" in _module:
        continue
    print(f"{frame.filename}:{frame.lineno} in {frame.name}")

/project/instblog.py:18 in <module>
/project/venv/lib/python3.14/site-packages/instructor/v2/core/client.py:543 in create
/project/venv/lib/python3.14/site-packages/instructor/v2/core/patch.py:252 in new_create_sync
/project/venv/lib/python3.14/site-packages/instructor/v2/core/retry.py:183 in retry_sync_v2
/project/venv/lib/python3.14/site-packages/openai/_utils/_utils.py:266 in wrapper
<string>:2 in <module>
```

This illustrates how Instructor leverages the underlying OpenAI Python API.

The Instructor client called `client.create` to kick off the LLM step. I'll save you some debugging steps and reveal that this exists in this part of the source code, the method with this heavily truncated signature:

```python
    @required_args(["messages", "model"], ["messages", "model", "stream"])
    def create(...)
```

We can set a breakpoint there and backtrace again:

```
/project/instblog.py:18 in <module>
/project/venv/lib/python3.14/site-packages/instructor/v2/core/client.py:543 in create
/project/venv/lib/python3.14/site-packages/instructor/v2/core/patch.py:252 in new_create_sync
/project/venv/lib/python3.14/site-packages/instructor/v2/core/retry.py:183 in retry_sync_v2
/project/venv/lib/python3.14/site-packages/openai/_utils/_utils.py:298 in wrapper
/project/venv/lib/python3.14/site-packages/openai/resources/chat/completions/completions.py:1283 in create
```

The first line of the implementation shows that the model is validated and a POST request to the appropriate API:

```python
        validate_response_format(response_format)
        return self._post(
            "/chat/completions",
```

Our intuition from earlier is now challenged. Instructor decided to send this request to the chat completions API, and not the Responses API. So we should wonder how it's even handling the structured output.

If we step into the `self._post` call, we find a line that constructs the underlying `httpx` request, then sends the request:

```
        opts = FinalRequestOptions.construct(
            method="post", url=path, json_data=body, content=content, files=to_httpx_files(files), **options
        )
        return cast(ResponseT, self.request(cast_to, opts, stream=stream, stream_cls=stream_cls))

```

We can inspect the `opts` value in the debugger:

```
FinalRequestOptions(
method='post', 
url='/chat/completions', 
params={}, 
headers=NOT_GIVEN, 
max_retries=NOT_GIVEN, 
timeout=NOT_GIVEN, 
files=None, 
idempotency_key=None, 
post_parser=NOT_GIVEN, 
follow_redirects=None, 
security={'bearer_auth': True}, 
synthesize_event_and_data=None, 
content=None, 
json_data={'messages': [{'role': 'user', 'content': 'Extract: John is a 30-year-old software engineer'}], 'model': 'gpt-4o', 'tool_choice': {'type': 'function', 'function': {'name': 'Person'}}, 'tools': [{'type': 'function', 'function': {'name': 'Person', 'description': 'Correctly extracted `Person` with all the required parameters with correct types', 'parameters': {'properties': {'name': {'title': 'Name', 'type': 'string'}, 'age': {'title': 'Age', 'type': 'integer'}, 'occupation': {'title': 'Occupation', 'type': 'string'}}, 'required': ['age', 'name', 'occupation'], 'type': 'object'}}}]}, 
extra_json=None)
```

The `json_data` contains the same `messages` block that we gave it in the original invocation from the toy code example earlier. However, we also observe two interesting fields here: `tool_choice` and `tools`. As noted earlier, this is expected because we're using the default "tools" mode, but let's explore it a little more.

The [`tool_choice` parameter](https://developers.openai.com/api/reference/python/resources/chat/subresources/completions/methods/create#(resource)%20chat.completions%20%3E%20(method)%20create%20%3E%20(params)%20default.non_streaming%20%3E%20(param)%20tool_choice%20%3E%20(schema)) tells the completions API to use a specific tool. Notice that the name of this tool matches the Pydantic base model we defined in the code earlier:

```
print(json.dumps(opts.json_data['tool_choice'], indent=2))

{
  "type": "function",
  "function": {
    "name": "Person"
  }
}
```

The [`tools` array](https://developers.openai.com/api/reference/python/resources/chat/subresources/completions/methods/create#(resource)%20chat.completions%20%3E%20(method)%20create%20%3E%20(params)%20default.non_streaming%20%3E%20(param)%20tools%20%3E%20(schema)) defines our schema *as a tool*, along with explicit instructions to use it as such:

```
print(json.dumps(opts.json_data['tools'][0], indent=2))

{
  "type": "function",
  "function": {
    "name": "Person",
    "description": "Correctly extracted `Person` with all the required parameters with correct types",
    "parameters": {
      "properties": {
        "name": {
          "title": "Name",
          "type": "string"
        },
        "age": {
          "title": "Age",
          "type": "integer"
        },
        "occupation": {
          "title": "Occupation",
          "type": "string"
        }
      },
      "required": [
        "age",
        "name",
        "occupation"
      ],
      "type": "object"
    }
  }
}
```

This schema is identical to the `Person.model_dump_schema()` and is implemented in Pydantic's base models.

So, in the backend, Instructor didn't really "resolve" an API. It just used the chat completions API and defined the schema as a tool.

For clarity, Instructor does allow you to invoke the `responses.create` function explicitly. A better way to handle this is by specifying the `RESPONSES_TOOLS` mode in the constructor. This is the only code change we need to make:

```python
client = instructor.from_provider(
    "openai/gpt-5.6-luna",
    mode=instructor.Mode.RESPONSES_TOOLS
)
```

This would work, but only if your model or provider supports the Responses API. OpenAI and HuggingFace both do. Ollama and many others do not natively support it. Even the smaller `gpt-4o` does not support it (which is why I changed the model in this code change).

Using this version kicks off the request against the responses API, using the same `self._post` method but with different parameters:

```
/projects/instblog.py:21 in <module>
/projects/venv/lib/python3.14/site-packages/instructor/v2/core/client.py:101 in create
/projects/venv/lib/python3.14/site-packages/instructor/v2/core/client.py:543 in create
/projects/venv/lib/python3.14/site-packages/instructor/v2/core/patch.py:252 in new_create_sync
/projects/venv/lib/python3.14/site-packages/instructor/v2/core/retry.py:183 in retry_sync_v2
/projects/venv/lib/python3.14/site-packages/instructor/v2/providers/openai/client.py:23 in map_chat_completion_to_response
/projects/venv/lib/python3.14/site-packages/openai/resources/responses/responses.py:1004 in create
/projects/venv/lib/python3.14/site-packages/openai/_base_client.py:1346 in post
```

We can dump these parameters as we did earlier:

```
print(opts)

method='post' url='/responses' params={} headers=NOT_GIVEN max_retries=NOT_GIVEN timeout=NOT_GIVEN files=None idempotency_key=None post_parser=NOT_GIVEN follow_redirects=None security={'bearer_auth': True} synthesize_event_and_data=None content=None json_data={'input': [{'role': 'user', 'content': 'Extract: John is a 30-year-old software engineer'}], 'model': 'gpt-5.6-luna', 'tool_choice': {'type': 'function', 'name': 'Person'}, 'tools': [{'type': 'function', 'name': 'Person', 'parameters': {'properties': {'name': {'title': 'Name', 'type': 'string'}, 'age': {'title': 'Age', 'type': 'integer'}, 'occupation': {'title': 'Occupation', 'type': 'string'}}, 'required': ['name', 'age', 'occupation'], 'title': 'Person', 'type': 'object', 'additionalProperties': False}, 'description': 'Correctly extracted `Person` with all the required parameters with correct types'}]} extra_json=None
```

Aside from the model and URL base path, we can see that the request was still set up by defining the rdesired schema as a tool. The [`tools`](https://developers.openai.com/api/reference/python/resources/responses/methods/create#(resource)%20responses%20%3E%20(model)%20tool_choice_allowed%20%3E%20(schema)%20%3E%20(property)%20tools) and [`tool_choice`](https://developers.openai.com/api/reference/python/resources/responses/methods/create#(resource)%20responses%20%3E%20(model)%20response%20%3E%20(schema)%20%3E%20(property)%20tool_choice) parameters are also available in the Responses API. In terms of the HTTP request structure, this behavior is identical. 

As a final note, here's what happens when we use `instructor.Mode.JSON_SCHEMA`, which implicitly calls the Chat Completions API:

```
method='post' 
url='/chat/completions' (...)
'model': 'gpt-5.6-luna', 
'response_format': { (...)'title': 'Person', 'type': 'object'}}}} 
extra_json=None
```

This mode uses the [Chat Completions' `response_format` parameter](https://developers.openai.com/api/reference/python/resources/chat/subresources/completions/methods/create#(resource)%20chat.completions%20%3E%20(method)%20create%20%3E%20(params)%20default.non_streaming%20%3E%20(param)%20response_format%20%3E%20(schema)) to inject the schema.

> response_format: Optional[[ResponseFormat](https://developers.openai.com/api/reference/python/resources/chat/subresources/completions/methods/create#(resource) chat.completions > (method) create > (params) default.non_streaming > (param) response_format > (schema))]
>
> An object specifying the format that the model must output.
>
> Setting to `{ "type": "json_schema", "json_schema": {...} }` enables Structured Outputs which ensures the model will match your supplied JSON schema. Learn more in the [Structured Outputs guide](https://platform.openai.com/docs/guides/structured-outputs). 

The crucial observation here is that Instructor appears to be opinionated about how it selects a provider's API, but that shouldn't stop you from understanding your options and following best practices. You can programmatically set API parameters or override Instructor's client functions to taste. Put another way, don't sweat the details unless you have to.

A sole word of caution, which is true of any platform abstraction library: if the provider changes the API spec, the library must also update. So long as the Instructor team maintains their code API to match the provider, this is a nonissue. But it is something to keep in mind if your solution breaks later down the road.

### Corner Case: Mixing Output Types

Instructor has an advantage over many native code APIs: support for multiple output types. Suppose you have a new Pydantic BaseModel called `Place`. You could use the `Person` and `Place` schemas like so:

```python
person = client.responses.create(
    response_model=Person | Place,
    ...
```

As we saw earlier, whether this is sent as a tool or something else is irrelevant. The point is that it is trivial.

OpenAI's Chat Completions and Responses APIs lack this native ability. There are some ways to get around it. None of them are particularly attractive.

An easy win is to create a new base model that serves as a "wrapper" for all desired schemas.

```python
class EventOrPlace(BaseModel):
    output: Union[CalendarEvent, WeatherQuery]
    
response = client.responses.parse(
    text_format=EventOrPlace
    ...
```

The output is chosen automatically by the LLM:

```
# Question: What is the weather in Tokyo?
output=WeatherQuery(city_name='Tokyo')

# Question: Alice and Bob want to go to the moves on June 17, 2027
output=CalendarEvent(name='Go to the movies', date='June 17, 2027', participants=['Alice', 'Bob'])
```

The side effects are less obvious until you have to work with the data. Notice that we store the result in the `output` variable. Before we access our data, we have to reference that `output` variable every single time. This is inconvenient and becomes less convenient if at any point in your code you change the "union variable" name.

An alternative approach has been implied so far but not strictly used: convert both schemas to a tool.

```
response = client.responses.parse(
    tools=[
        {
            'type': 'function',
            'name': 'CalendarEvent',
            'parameters': CalendarEvent.model_json_schema(),
            'additionalProperties': False
        },
        {
            'type': 'function',
            'name': 'WeatherQuery',
            'parameters': WeatherQuery.model_json_schema(),
            'additionalProperties': False
        }
    ]
    ...
```

Then access the structured output from `response.output[N].arguments`:

```
response.output[0].name
'WeatherQuery'

response.output[0].arguments
'{"city_name":"Tokyo"}'
```

There's ways you can make this more manageable, but the point is that it's less straightforward. If structured output is your goal and this is your constraint, consider a union. If other factors make the union type unmanageable, implement the schemas as a tool.

### Corner Case: Mixing Tools and Structured Output

Structured output doesn't come without its costs. One cost is the usage of both tools and structured outputs all in one invocation.

Earlier, we called out the `tool_choice` object in the parameters. This explicitly tells a model that it must use one specific tool. In the previous examples, the tool is defined based on the base model's schema; this is how it enforces the output format.

Suppose we try to define a simple tool that follows the [Responses API schema](https://developers.openai.com/api/reference/python/resources/responses/methods/create#(resource)%20responses%20%3E%20(model)%20function_tool%20%3E%20(schema)):

```python
get_weather_tool = {
    "type": "function",
    "name": "get_weather",
    "description": "Get the current weather for a city.",
    "parameters": {
        "type": "object",
        "properties": {
            "city": {
                "type": "string",
                "description": "The city name."
            },
            "units": {
                "type": "string",
                "enum": ["celsius", "fahrenheit"]
            },
        },
        "required": ["city"],
        "additionalProperties": False,
    },
}
```

> Note: This tool is spec'ed against the Responses API. Tool definitions for the Chat Completions API are small, but Chat Completions will reject this tool.

I'll pause for a moment and call out something. As far as API providers are concerned, a "tool" is generally something that you, the developer. The LLM's job is to say, "Given the question, what tool do I think is best for the task?" The LLM has no awareness of the tool's definition or expected use cases beyond this context.

So, we have *defined* a tool, but we haven't *implemented* anything it can do. This is fine for a discussion on "What does the LLM see when it uses tools?"

This distinction becomes important when you're developing tools in code and MCP servers, whose frameworks usually abstraction these details from the developer but provid this context to the LLM. For now, we'll accept that we haven't actually implemented this in code. We don't have to for this example.

We can use it in a simple driver code:

```python
response = client.responses.parse(
    model="gpt-5.6-luna",
    input=[
        {"role": "system", "content": "Extract the event information."},
        {
            "role": "user",
            "content": "Alice and Bob are going to a science fair on Friday.",
        },
    ],
    text_format=CalendarEvent,
    tools=[
        get_weather_tool
    ]
)
```

If we try this in an invocation of OpenAI's `client.responses.parse`, we get the following exception:

```
Exception has occurred: Exception
Expected Chat Completions function tool shape to be created using `openai.pydantic_function_tool()`
...
Exception: Expected Chat Completions function tool shape to be created using `openai.pydantic_function_tool()`

```

In other words, the code API expected only a Pydantic base model.

Likewise, the `cient.responses.create` method doesn't allow for explicit structured output at all.

```
Responses.create() got an unexpected keyword argument 'text_format'
```

You can observe a similar behavior with the Chat Completions API, which also exposes `create` and `parse` methods.

The only workaround is to accept the following facts. The first is that you won't be able to *cleanly* implement your solution. The second is that, should you choose to work around this, you're ultimately telling the LLM:

> Based on the user's question, either give me a structured output response or the desired tool invocation name/parameters.

To implement this, we can do one of two possible things:

- For Responses only, hijack the `text` parameter.

- For Chat Completions and Responses, implement the schema as another tool

A full implementation for the second case would look like this:

```python
from openai import OpenAI
from pydantic import BaseModel
from manual_tool import get_weather_tool

client = OpenAI()


class CalendarEvent(BaseModel):
    name: str
    date: str
    participants: list[str]


schema = CalendarEvent.model_json_schema()
schema['additionalProperties'] = False

response = client.responses.create(
    model="gpt-5.6-luna",
    input=[
        {"role": "system", "content": "Extract the event information."},
        {
            "role": "user",
            "content": "Tell me the weather in Tokyo",
        },
    ],
    text={
        "format": {
            "type": "json_schema",
            "name": "calendar_event",
            "schema": schema,
        }
    },
    tools=[get_weather_tool],
)

event = response.output_parsed

```

Now consider two different response possibilities. 

In the first possibility, you get the name and arguments for the function you want to call:

```
Question: "Tell me the weather in Tokyo"

response.output[1]

ResponseFunctionToolCall(arguments='{}', call_id='call_QPttpUjryMHsvWmoDMRF4dMV', name='get_weather', type='function_call', id='fc_010dc9a5517e8714006a67dc43283c81a0a2648f0dd2855a74', caller=None, namespace=None, status='completed')
```

In the second possibility, you get the structured output, but you have to do some work to get it.

```
Question: "Alice and Bob want to go to the movies on July 17, 2027"

json.loads(response.output[1].content[0].text)

{'name': 'Go to the movies', 'date': 'July 17, 2027', 'participants': ['Alice', 'Bob']}
```

On the surface, this approach seems like a workable solution. But there are some limitations:

- As seen above, the accessor logic is reprehensible
- You can only define one possible schema
- You have two different ways to retrieve two different sets of data

One of the benefits of schemas is that you can allow the LLM to choose one dynamically. The `text` field defies this, and the reason should be intuitive: the Responses API wants you to use `requests.parse` which, as we've discovered, is not necessarily what we want.

A cross-API solution might also include treating the schema as a new tool, similar to what we did to mix schemas:

```python
response = client.responses.create(
    tools=[
        get_weather_tool,
        {
            'type': 'function',
            'name': 'CalendarEvent',
            'parameters': CalendarEvent.model_json_schema(),
        },
        {
            'type': 'function',
            'name': 'JobTitle',
            'parameters': JobTitle.model_json_schema(),
        }
    ]
    ...
```

As before, the schema is in the arguments:

```
# What is the weather in Tokyo?
response.output[0].name, response.output[0].arguments 
('get_weather', '{"city":"Tokyo","units":"celsius"}')

# Alice and Bob want to see a movie on July 17, 2027.
response.output[1].name, response.output[1].arguments 
('CalendarEvent', '{"name":"See a movie","date":"July 17, 2027","participants":["Alice","Bob"]}')

# Sally is a Lead Engineer.
response.output[1].name, response.output[1].arguments 
('JobTitle', '{"job_title":"Lead Engineer"}')
```

Instructor also inherits this problem, and hopefully the reason why is a little more clear now. Instructor's claim to fame is really structured output and text extraction. The possibility for tool invocation challenges it's core use cases.

This leads into "what else" you can use in order to handle nuances like multiple schemas, multiple tools, and more, all coexisting together. Well folks, unfortunately, the answer is less straightforward than the current approach. At this point, you're starting to describe an *agent*.

## Are you actually writing an agent?

Instructor provides the [following guidance on the project's homepage](https://python.useinstructor.com/):

> **Instructor for extraction, PydanticAI for agents.**  Instructor shines when you need fast, schema-first extraction without  extra agents. When your project needs quality gates, shareable runs, or built-in observability, try [PydanticAI](https://ai.pydantic.dev/). PydanticAI is the official agent runtime from the Pydantic team: it  adds typed tools, dataset replays, and production dashboards while  keeping your existing Instructor models. Read the [PydanticAI docs](https://ai.pydantic.dev/) to see how to bring those capabilities into your stack.

Agents can be simple and they can be complex. You can roll your own using a simple while-tool/while-schema logic or you can use a homebuilt framework. Modern agents are sophisticated, but they don't have to be.

Before you refactor your codebase to use agents, I will say that agents can incur a huge cost, a literal cost in dollars-and-cents. Agents can consume tens of thousands of tokens and give you invalid answers or bottom-out before they have a chance to finish. This is especially true of prebuilt frameworks, including SmolAgents, PydanticAI, and the Lang\* series.

If you think you're secretly writing an agent, but you also think your workflow needs to be simple, try this:

- Implement your schemas and tools all as tools
- Define a while loop
- Set a terminating condition defined by the LLM (for example, this could be a schema or a "done" string from the LLM)
- For non-terminating conditions, perform actions within the loop based on the tool or schema returned
- On every loop iteration, track or print your input and output tokens separately

A reference implementation can be found [here](https://modelcontextprotocol.io/docs/develop/build-client).

If the cost of this loop is at least 15-20k tokens, you should accept that you're secretly writing an agent, but deluding yourself into thinking that you're still writing an AI workflow. You can certainly continue with this approach if you're happy with it or if it's cheaper given the use case. 

We end this section with just a bit more code. Let's use the many-tool Responses API harness, but with the following changes:

```python
response = client.responses.create(
    model="gpt-5.6-luna",
    input=[
        {"role": "system", "content": "Answer the user's question"},
        {
            "role": "user",
            "content": (
                "Alice and Sally want to see a movie in Tokyo, Japan on Aug 01, 2027, "
                "but if it's sunny, they would rather go to the beach. "
                "Also, Sally's job as a Project Manager makes this it so hard to plan these things!"
            ),
        },
    ],
    tools=[
        get_weather_tool,
        {
            "type": "function",
            "name": "CalendarEvent",
            "parameters": CalendarEvent.model_json_schema(),
        },
        {
            "type": "function",
            "name": "JobTitle",
            "parameters": JobTitle.model_json_schema(),
        },
    ],
)

N = len(response.output) - 1

event = (
    response.output[N].name,
    response.usage.input_tokens,
    response.usage.output_tokens,
)
print(event)
```

Here, I intentionally give the LLM an ambiguous system prompt and user prompt. This does not fit inside any loop logic at all. The LLM will do its best to give me an answer. I will remain uncertain as to what that answer actually is.

Over five iterations, track the output and cost:

```
('JobTitle', 177, 219)
('JobTitle', 177, 210)
('CalendarEvent', 177, 444)
('CalendarEvent', 177, 446)
('CalendarEvent', 177, 238)
```

Given the ambiguous nature of this query, it seems reasonable that the model did not necessarily try to run a tool, or that it had a seemingly arbitrary output schema. Garbage in, garbage out, tokens burned.

> Note: This run was pennies on the dollar given the per-million pricing model. But these activities quickly rack up a bill if you're not careful. You've been warned.

Now, let's consider an equivalent approach using PydanticAI:

```python
from pydantic_ai import Agent
from pydantic import BaseModel, Field
from manual_tool import get_weather_tool
from dotenv import load_dotenv

load_dotenv()


class CalendarEvent(BaseModel):
    name: str
    date: str
    participants: list[str]


class JobTitle(BaseModel):
    job_title: str


agent = Agent(
    model="openai:gpt-5.6-luna",
    instructions="Answer the user's question",
)


@agent.tool_plain
def get_weather(city: str) -> str:
    """
    Get the weather for a particular city.

    Args:
    city (str): The name of the city to forecast

    Returns:
    str: The weather forecast
    """
    print("Tool invocation...")
    return "It will be sunny in New York on Aug 01, 2027"


result = agent.run_sync(
    (
        "Alice and Sally want to see a movie in Tokyo, Japan on Aug 01, 2027, "
        "but if it's sunny, they would rather go to the beach. "
        "Also, Sally's job as a Project Manager makes this it so hard to plan these things!"
    ),
    output_type=[CalendarEvent, JobTitle],
)

print(result, result.usage.input_tokens, result.usage.output_tokens)
```

There are two major differences between the two solutions:

- The `get_weather` tool is now inbuilt using PydanticAI's agent native tool definition approach. It looks a little more like how you would define an MCP tool. It's framework-native, platform-agnostic, and readable. This is a Good ThingTM. In reality, the `Agent` constructor has an optional `tools` argument, which accepts a list of ugly tools, MCP clients, and more.
- The agent's constructor accepts an argument called `instructions`. There is no system prompt defined in this solution.

The [`instructions`](https://developers.openai.com/api/reference/python/resources/responses/methods/create#(resource)%20responses%20%3E%20(method)%20create%20%3E%20(params)%20default.non_streaming%20%3E%20(param)%20instructions%20%3E%20(schema)) parameter is defined in the Responses API: 

> A system (or developer) message inserted into the model’s context.
>
> When using along with `previous_response_id`, the instructions from a previous response will not be carried over to the next response. This makes it simple to swap out system (or developer) messages in new responses.

So, this is more of a convenience when processing chains of thought between the agent's internal multishots. The key factor is that it still serves as a privileged prompt, which a user prompt cannot override or replace. Functionally, this should serve as a system prompt which is better suited for an agentic context.

PydanticAI also [distinguishes when to use one or the other](https://pydantic.dev/docs/ai/core-concepts/agent/#instructions):

> You should use:
>
> - `instructions` when you want your request to the model to only include system prompts for the *current* agent
> - `system_prompt` when you want your request to the model to *retain* the system prompts used in previous requests (possibly made using other agents)
>
> In general, we recommend using `instructions` instead of `system_prompt` unless you have a specific reason to use `system_prompt`.

For now, let's run with the assumption that we should use *instructions* and not assume that the `system_prompt` will behave as it did in other frameworks.

Unlike in the other solution, we actually implemented the tool, instead of just describing it. As a convenience, we implemented it in such a way that prints when it is invoked.

```
Tool invocation...
AgentRunResult(output=CalendarEvent(name='Beach day in Tokyo (sunny-weather plan)', date='2027-08-01', participants=['Alice', 'Sally'])) 468 199
```

As we did with instructor, we can debug a path to the point where the underlying OpenAI library's request is made.

```
class AsyncAPIClient(BaseClient[httpx.AsyncClient, AsyncStream[Any]]):
    ...
    async def request(
        ...
            request = self._build_request(options, retries_taken=retries_taken)
            ...
            try:
                response = await self._send_request(
```

Dump the `request` object to analyze its content:

```
print(request)
<Request('POST', 'https://api.openai.com/v1/responses')>

print(options.json_data["instructions"])
"Answer the user's question"

options.json_data["input"]
[{'role': 'user', 'content': "Alice and Sally want to see a movie in Tokyo, Japan on Aug 01, 2027, but if it...akes this it so hard to plan these things!'}]

options.json_data.get("messages") or "messages key not found"
'messages key not found'
```

True to the Requests API guidance, the `instructions` now serve as the `system_prompt` from the earlier discussion, and `input` replaces the use of `messages` altogether. This should preserve our assumptions about the overall prompt security and the model's overall reasoning.

Here's the cost breakdown of the first five runs of the agent-less solution:

| Run       | Tool invoked? | Input   | Output    | Cost          |
| --------- | ------------- | ------- | --------- | ------------- |
| 1         | No            | 177     | 219       | **$0.001491** |
| 2         | No            | 177     | 210       | **$0.001437** |
| 3         | No            | 177     | 444       | **$0.002841** |
| 4         | No            | 177     | 446       | **$0.002853** |
| 5         | No            | 177     | 238       | **$0.001605** |
| **Total** | 0%            | **885** | **1,557** | **$0.010227** |

And here's the cost/capabilities breakdown of five runs with the PydanticAI agent:

| Run       | Tool invoked? | Input     | Output    | Cost          |
| --------- | ------------- | --------- | --------- | ------------- |
| 1         | Yes           | 468       | 199       | **$0.001662** |
| 2         | No            | 194       | 135       | **$0.001004** |
| 3         | Yes           | 518       | 210       | **$0.001778** |
| 4         | Yes           | 545       | 275       | **$0.002195** |
| 5         | Yes           | 497       | 329       | **$0.002471** |
| **Total** | 80%           | **2,222** | **1,148** | **$0.009110** |

One observation here is that the agent used almost triple the amount of input tokens. This is in no small part due to its usage of the agent-native weather tool, which it invoked most of the time. But input tokens are fairly cheap, so this is not the worst thing that could happen. 

In terms of cost-per-run, the agent turned out to be the winner. Not only could it invoke tools (and did so most of the time), but the overall usage in output tokens was marginally lower.

But it wasn't a winner by much, and again, the inputs were both simple and ambiguous. This is almost certainly because of the sheer volume of retrofitting we made to the original solution: namely, its impact on the output token volume. You could try to mitigate that by creating each output type/tool call in its own step to the `client`, but that's beyond the scope of this article. Funky solutions aren't always the best fit. 

The difference in the bottom line is hard to appreciate and probably not intuitive. Every time an agent runs, the output from tools, thinking steps, and other factors gets fed into its per-run context window. You would think that this would burn way more money.

Here's an observation, one that directly links to the next section. Agents get expensive. They do get hard to manage and hard to monitor. This is not a bulletproof solution, and over enough runs, it's possible that a clear distinction would emerge.

But agent frameworks are designed to help with that. If you suspect that you're secretly writing an agent, try writing an agent. Otherwise, it's still an agent, but with more code.

The big mindset shift is that the agent handles tools, thinking steps, and intermediary steps. You'll have to account for edge cases where the black-box nature of an agent needs some tweaking, auditing, and customization. Use tools and other features provided by the framework to get it to a manageable state.

The original solution might work for you. If you're happy with it, keep it.

But there may come a time when your solution outgrows the implementation you gave it today. At that time, start looking at agent frameworks. They'll do everything your loop does, but better and cleaner. If you can invest the time to develop your agent, it may do so at an equivalent price.