from ..functions.api_request import api_request

async def create_saving(amount: str, deposit: str):
  api_response = await api_request("POST", "/saving/create", "", {"amount": amount, "deposit": deposit})
  return api_response

async def withdraw_saving():
  api_response = await api_request("GET", "/saving/withdrawals", "", None)
  return api_response

async def claim(request_ids):
  api_response = await api_request("POST", "/saving/refund", '', {"request_ids": request_ids})
  return api_response