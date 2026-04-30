content = open('/etc/timesketch/timesketch.conf').read()

content = content.replace(
    '"nl2q": {\n        "vertexai": {\n            "model": "gemini-2.0-flash",\n            "project_id": "",\n        },\n    },',
    '"nl2q": {\n        "ollama": {\n            "server_url": "http://172.17.0.1:11434",\n            "model": "llama3.2:1b",\n        },\n    },'
)

content = content.replace(
    '"llm_summarize": {\n        "vertexai": {\n            "model": "gemini-2.0-flash",\n            "project_id": "",\n        },\n    },',
    '"llm_summarize": {\n        "ollama": {\n            "server_url": "http://172.17.0.1:11434",\n            "model": "llama3.2:1b",\n        },\n    },'
)

content = content.replace(
    '"ollama": {\n            "server_url": "",\n            "model": "",\n        },',
    '"ollama": {\n            "server_url": "http://172.17.0.1:11434",\n            "model": "llama3.2:1b",\n        },'
)

open('/etc/timesketch/timesketch.conf', 'w').write(content)
print('Konfiguration aktualisiert')
