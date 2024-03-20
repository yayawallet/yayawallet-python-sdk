from ..functions.api_request import api_request

async def get_transaction_list_by_user():
  api_response = await api_request("GET", "/transaction/find-by-user", "?p=1", None)
  return api_response

async def create_transaction(receiver: str, amount: str, cause: str, meta_data: str):
  api_response = await api_request("POST", "/transaction/create", "", {"receiver": receiver, "amount": amount, "cause": cause, "meta_data": meta_data})
  return api_response

async def transaction_fee(receiver: str, amount: str):
  api_response = await api_request("POST", "/transaction/fee", "", {"receiver": receiver, "amount": amount})
  return api_response

async def generate_qr_url(amount: str, cause: str):
  api_response = await api_request("POST", "/transaction/qr-generate", "", {"amount": amount, "cause": cause})
  return api_response

async def get_transaction_by_id(id: str):
  api_response = await api_request("GET", "/transaction/" + id, "", None)
  return api_response

async def search_transaction(query: str):
  api_response = await api_request("POST", "/transaction/search", "", {"query": query})
  return api_response