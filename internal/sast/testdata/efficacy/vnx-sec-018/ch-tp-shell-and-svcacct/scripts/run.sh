#!/bin/sh
~>export HF_TOKEN=hf_@@sample:[A-Za-z]{34}@@
~>OPENAI_API_KEY='sk-svcacct-@@sample:[A-Za-z0-9]{64}@@' python batch.py
