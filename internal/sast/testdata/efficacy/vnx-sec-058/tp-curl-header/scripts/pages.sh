#!/bin/sh
curl https://api.notion.com/v1/pages \
~>  -H 'Authorization: Bearer ntn_@@sample:[0-9]{11}@@@@sample:[A-Za-z0-9]{35}@@' \
  -H 'Notion-Version: 2022-06-28'
