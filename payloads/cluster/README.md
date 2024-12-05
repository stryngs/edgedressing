## What
cluster is a payload for forcing the target to load many websites using iframes.  Simply modify domains.txt to choose the websites visited.

Running svr.py with no parameters produces an index.html file that leverages javascript to not load all the iframes at once.

Running svr.py with the --flood parameter produces an index.html file with no javascript that loads all the iframes at once.

## How
ChatGPT and live testing feedback to the prompt.
