from net_util_api import api
from net_util_mcp import mcp_app

api.mount("/llm", mcp_app)