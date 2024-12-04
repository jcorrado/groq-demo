#!/bin/bash

set -v

curl https://groq.jcorrado.dev/openai/v1/chat/completions -s \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $GROQ_API_KEY" \
-d '{
"model": "llama3-8b-8192",
"messages": [{
    "role": "user",
    "content": "Why does ghost-george insist on offering me chips? He knows I cant grab his ghost chips."
}]
}' | jq '{object, model, content: .choices[0].message.content, x_groq}'
