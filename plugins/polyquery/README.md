# PolySwarm CyBot Plugin

This plugin allows chat bot queries to the PolySwarm threat detection marketplace. 
You'll need to obtain an API key at https://polyswarm.network and setup this
plugin according to the below. 

Currently this uses a beta version of polyswarm-api and you'll need Python 3.5+.

## Setup

1. Obtain an API key by signing up at https://polyswarm.network
1. Set the API key obtained above to env variable at `POLYSWARM_API_KEY` within your errbot environment
1. Run errbot with this plugin in directory

On first run errbot should install dependencies in `requirements.txt`

