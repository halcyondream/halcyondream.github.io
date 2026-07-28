# Code Deep Dives

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

## Analyzing Instructor's use of provider APIs

In the book review, I only superficially covered Instructor. Their developer documentation is rich and the project offers a lot of useful features. I'll cover some edge cases and deep dives that was left outside of the book's scope.

Under the hood, most of the Instructor providers secretsly use the provider's upstream code/web APIs. Let's explore two such APIs, the chat completions and the responses API, as they are used by OpenAI.

First, an example of Python's usage of the chat completions API:

```python
from openai import OpenAI
client = OpenAI()

completion = client.chat.completions.create(
  model="VAR_chat_model_id",
  messages=[
    {"role": "developer", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ]
)

print(completion.choices[0].message)
```

If you read the docs, you'll notice an absence of any type of structured output parameters; this is the whole problem that Instructor helps us solve. Some practical sources on the web will say that you can handle it in the context window or by defining a tool that achieves the same goal. This approach is ugly at best.

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

By default, clients use the `mode=instructor.Mode.TOOLS` under the hood. This converts each structured output to the provider's native tool format. Other options, like `instructor.Mode.JSON_SCHEMA` will make a best-effort attempt to leverage the provider API's native structured-text fields if those options are available. For now, the tool mode is fine.

The `create` method doesn't really tell us anything about the API in use. The Chat Completions API and Responses API both support a `create` operation. The first question we should ask is: does it matter which API it uses?

This is a big question and I'm not going to weigh in. For "best practices," this may be something you need to explore. For security, you might consider any differences between access control/authorization, validation, etc.

For now, let's pretend the question matters.

If you run this script in a debugger, set a breakpoint at `client.create`, and step into it, you can begin tracing the point at which Instructor actually crosses over into the OpenAI package:

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

Instructor's big claim to fame is in how it handles structured output. But some providers support different APIs for a given request. OpenAI specifically supports the chat completion's API as well as its new responses API, which it recommends for structured output cases, like this. (To make things a little more confusing, neither of these should be confused with the outdated "completions" API.)

Which one does instructor pick?

Intuition says that it picks the best one for the job. But that might not always be true. Let's investigate.

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

```
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
FinalRequestOptions(method='post', url='/chat/completions', params={}, headers=NOT_GIVEN, max_retries=NOT_GIVEN, timeout=NOT_GIVEN, files=None, idempotency_key=None, post_parser=NOT_GIVEN, follow_redirects=None, security={'bearer_auth': True}, synthesize_event_and_data=None, content=None, json_data={'messages': [{'role': 'user', 'content': 'Extract: John is a 30-year-old software engineer'}], 'model': 'gpt-4o', 'tool_choice': {'type': 'function', 'function': {'name': 'Person'}}, 'tools': [{'type': 'function', 'function': {'name': 'Person', 'description': 'Correctly extracted `Person` with all the required parameters with correct types', 'parameters': {'properties': {'name': {'title': 'Name', 'type': 'string'}, 'age': {'title': 'Age', 'type': 'integer'}, 'occupation': {'title': 'Occupation', 'type': 'string'}}, 'required': ['age', 'name', 'occupation'], 'type': 'object'}}}]}, extra_json=None)
```

The `json_data` contains the same `messages` block that we gave it in the original invocation from the toy code example earlier. However, we also observe two interesting fields here: `tool_choice` and `tools`. As noted earlier, this is expected because we're using the default "tools" mode, but let's explore it a little more.

The `tool_choice` tells the completions API to use a specific tool. Notice that the name of this tool matches the Pydantic base model we defined in the code earlier:

```
print(json.dumps(opts.json_data['tool_choice'], indent=2))

{
  "type": "function",
  "function": {
    "name": "Person"
  }
}
```

The `tools` array defines our schema *as a tool*, along with explicit instructions to use it as such:

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

Is this a bad thing? It's hard to say. The completions API is more supported than the responses API. But if you're developing to OpenAI explicitly, you probably want to follow their guidance and mitgrate to responses. Fundamentally, the results should be equivalent for text extraction, but that assumption could easily be broken depending on what you're trying to do.

For clarity, Instructor does allow you to invoke the `responses.create` function explicitly. This is the only code change we need to make:

```python
client = instructor.from_provider(
    "openai/gpt-5.6-luna",
    mode=instructor.Mode.RESPONSES_TOOLS
)

# Extract structured data from natural language
person = client.responses.create(
    ...
```

This would work, but only if your model or provider supports the Responses API. OpenAI and HuggingFace both do. Ollama and many others do not natively support it. Even the smaller `gpt-4o` does not support it (which is why I changed the model in this version).

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

Aside from the model and URL base path, we can see that the request was still set up by defining the rdesired schema as a tool. In terms of the request, this behavior is identical. 

This is an interesting observation. While the differences between the completions and requests endpoints are worthwhile in terms of functionality and OpenAI recommendations, they're still both glorified tool calls. I don't have further insight into what happens once OpenAI or any provider consumes either request, however. Take this similarity however you want.

The crucial observation here is that Instructor appears to be opinionated about how it selects a provider's API, but that might not be the end of the world. You can programmatically set API parameters or override Instructor's client functions to taste. Put another way, don't sweat the details unless you have to.

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

Suppose we try to define a simple tool:

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

This leads into "what else" you can use in order to handle nuances like multiple schemas, multiple tools, and more, all coexisting together. At this point, you're starting to describe an *agent*.

### Are you actually writing an agent?

Instructor provides the [following guidance on the project's homepage](https://python.useinstructor.com/):

> **Instructor for extraction, PydanticAI for agents.**  Instructor shines when you need fast, schema-first extraction without  extra agents. When your project needs quality gates, shareable runs, or built-in observability, try [PydanticAI](https://ai.pydantic.dev/). PydanticAI is the official agent runtime from the Pydantic team: it  adds typed tools, dataset replays, and production dashboards while  keeping your existing Instructor models. Read the [PydanticAI docs](https://ai.pydantic.dev/) to see how to bring those capabilities into your stack.

Agents can be simple and they can be complex. You can roll your own using a simple while-tool/while-schema logic or you can use a homebuilt framework. Modern agents are sophisticated, but they don't have to be.

Before you refactor your codebase to use agents, I will say that agents come with a huge cost, a literal cost in dollars-and-cents. Agents can consume tens of thousands of tokens and give you invalid answers or bottom-out before they have a chance to finish. This is especially true of prebuilt frameworks, including SmolAgents, PydanticAI, and the Lang\* series.

If you think you're secretly writing an agent, but you also think your workflow needs to be simple, try this:

- Implement your schemas and tools all as tools
- Define a while loop
- Set a terminating condition defined by the LLM (for example, this could be a schema or a "done" string from the LLM)
- For non-terminating conditions, perform actions within the loop based on the tool or schema returned
- On every loop iteration, track or print your input and output tokens separately

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

- The `get_weather` tool is now inbuild using PydanticAI's agent native tool definition approach. It looks a little more like how you would define an MCP tool. It's framework-native, platform-agnostic, and readable. This is a Good ThingTM. In reality, the `Agent` constructor has an optional `tools` argument, which accepts a list of ugly tools, MCP clients, and more.
- The agent's constructor accepts an argument called `instructions`. There is no system prompt defined in this solution.

PydanticAI [distinguishes the two](https://pydantic.dev/docs/ai/core-concepts/agent/#instructions):

> You should use:
>
> - `instructions` when you want your request to the model to only include system prompts for the *current* agent
> - `system_prompt` when you want your request to the model to *retain* the system prompts used in previous requests (possibly made using other agents)
>
> In general, we recommend using `instructions` instead of `system_prompt` unless you have a specific reason to use `system_prompt`.

For now, let's run with the assumption that we should use *instructions* and not system prompts.

Unlike in the other solution, we actually implemented the tool, instead of just describing it. As a convenience, we implemented it in such a way that prints when it is invoked.

```
Tool invocation...
AgentRunResult(output=CalendarEvent(name='Beach day in Tokyo (sunny-weather plan)', date='2027-08-01', participants=['Alice', 'Sally'])) 468 199
```

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

This is almost certainly because of the sheer volume of retrofitting we made to the original solution: namely, its impact on the output token volume. You could try to mitigate that by creating each output type/tool call in its own step to the `client`, but that's beyond the scope of this article. Funky solutions aren't always the best fit. 

The difference in the bottom line is hard to appreciate and probably not intuitive. Every time an agent runs, the output from tools, thinking steps, and other factors gets fed into its per-run context window. You would think that this would burn way more money.

Here's an observation, one that directly links to the next section. Agents get expensive. They do get hard to manage and hard to monitor. This is not a bulletproof solution, and over enough runs, it's possible that a clear distinction would emerge.

But agent frameworks are designed to help with that. If you suspect that you're secretly writing an agent, try writing an agent. Otherwise, it's still an agent, but with more code.

The big mindset shift is that the agent handles tools, thinking steps, and intermediary steps. You'll have to account for edge cases where the black-box nature of an agent needs some tweaking, auditing, and customization. Use tools and other features provided by the framework to get it to a manageable state.

The original solution might work for you. If you're happy with it, keep it.

But there may come a time when your solution outgrows the implementation you gave it today. At that time, start looking at agent frameworks. They'll do everything your loop does, but better, cleaner, and at an equivalent price.

In the next section, we'll cover tools for well-known and custom agents for an offensive security use case.

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