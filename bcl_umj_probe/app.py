from net_util_api import api, mcp_app

api.mount("/llm", mcp_app)