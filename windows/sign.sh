#!/bin/bash

APP_PATH="$1"

AzureSignTool sign -kvt ${AZURE_SIGN_TENANT_ID} \
  -kvu ${AZURE_SIGN_KEY_VAULT_URI} \
  -kvi ${AZURE_SIGN_CLIENT_ID} \
  -kvs ${AZURE_SIGN_CLIENT_SECRET} \
  -kvc ${AZURE_SIGN_CERT_NAME} \
  -tr http://timestamp.digicert.com -v "$APP_PATH"