import re
import sys

def remove_emojis(text):
    # This regex matches the majority of emoji blocks in Unicode
    emoji_pattern = re.compile(
        "["
        "\U0001f600-\U0001f64f"  # emoticons
        "\U0001f300-\U0001f5ff"  # symbols & pictographs
        "\U0001f680-\U0001f6ff"  # transport & map symbols
        "\U0001f1e0-\U0001f1ff"  # flags (iOS)
        "\U00002702-\U000027b0"
        "\U000024c2-\U0001f251"
        "\u200d\ufe0f\u26a0"
        "]+", flags=re.UNICODE)
    
    # Custom replacements for specific icons used in the code to keep formatting clean
    # The user wanted a clean professional look.
    replacements = [
        ("📊 ", ""), ("🔍 ", ""), ("📱 ", ""), ("🌐 ", ""), ("🧠 ", ""), ("📄 ", ""), ("💬 ", ""),
        ("✅", "✓"), ("⏳", "..."), ("⬜", " "), ("❌", "✕"), ("🚨 ", ""), ("🎯 ", ""), ("🔐 ", ""),
        ("🕵️ ", ""), ("🛡️ ", ""), ("⚡ ", ""), ("👮 ", ""), ("⚠️ ", ""), ("📋 ", ""), ("🔗 ", ""),
        ("📷 ", ""), ("🎮 ", ""), ("📥 ", ""), ("🚀 ", ""), ("📦 ", ""), ("🔑 ", ""), ("🎯", "")
    ]
    
    for old, new in replacements:
        text = text.replace(old, new)
        
    text = emoji_pattern.sub(r'', text)
    return text

with open('/home/rishabh/Desktop/genai/frontend/app/page.js', 'r') as f:
    content = f.read()

cleaned = remove_emojis(content)

with open('/home/rishabh/Desktop/genai/frontend/app/page.js', 'w') as f:
    f.write(cleaned)

print("Emojis stripped from page.js")
