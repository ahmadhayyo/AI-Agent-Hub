#!/bin/bash
# Push unpushed commits to GitHub
cd "$(dirname "$0")"
echo "Pushing commits to GitHub..."
git push origin main
echo "Done!"
