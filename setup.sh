#!/bin/bash
echo "🛠️  Setting up Argus Bulk Hunter..."

# Initialize submodules (pulls your Argus-Security fork)
git submodule update --init --recursive

# Install dependencies for the core Argus engine
if [ -d "argus-core" ]; then
    cd argus-core
    pip install -r requirements.txt -q
    pip install -e '.[scanners]' -q
    cd ..
else
    echo "❌ argus-core submodule missing."
    exit 1
fi

# Install dependencies for the hunter
pip install requests -q

echo "✅ Setup complete! Run 'python hunter.py' to start."
