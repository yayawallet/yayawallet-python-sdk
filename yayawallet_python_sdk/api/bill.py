from ..functions.api_request import api_request
from typing import Optional

async def create_bill(
    client_yaya_account: str,
    amount: float,
    due_at: str,
    customer_id: str,
    bill_id: str,
    customer_yaya_account: Optional[str] = None,
    start_at: Optional[str] = None,
    bill_code: Optional[str] = None,
    bill_season: Optional[str] = None,
    cluster: Optional[str] = None,
    description: Optional[str] = None,
    phone: Optional[str] = None,
    email: Optional[str] = None,
    details: Optional[str] = None,
    api_key: Optional[str] = None
  ):
    
  payload = {
    "client_yaya_account": client_yaya_account,
    "amount": amount,
    "due_at": due_at,
    "customer_id": customer_id,
    "bill_id": bill_id,
    **{
      key: value for key, value in {
        "customer_yaya_account": customer_yaya_account,
        "start_at": start_at,
        "bill_code": bill_code,
        "bill_season": bill_season,
        "cluster": cluster,
        "description": description,
        "phone": phone,
        "email": email,
        "details": details,
      }.items() if value is not None
    }
  }
    
  api_response = await api_request("POST", "/bill/create", "", payload, api_key)
  return api_response

async def create_bulk_bill(bulkBill, api_key = None):
  api_response = await api_request("POST", "/bulkimport/bills", "", bulkBill, api_key)
  return api_response

async def bulk_bill_status(param: Optional[dict] = None, api_key: Optional[str] = None) :
  page_number_param = param or {"p": 1}
  api_response = await api_request("GET", "/bulkimport/list", page_number_param, None, api_key)
  return api_response

async def update_bill(
  client_yaya_account: str,
  amount: float,
  due_at: str,
  customer_id: str,
  bill_id: str,
  customer_yaya_account: Optional[str] = None,
  start_at: Optional[str] = None,
  bill_code: Optional[str] = None,
  bill_season: Optional[str] = None,
  cluster: Optional[str] = None,
  description: Optional[str] = None,
  phone: Optional[str] = None,
  email: Optional[str] = None,
  details: Optional[str] = None,
  api_key: Optional[str] = None
):
    
  payload = {
    "client_yaya_account": client_yaya_account,
    "amount": amount,
    "due_at": due_at,
    "customer_id": customer_id,
    "bill_id": bill_id,
    **{
      key: value for key, value in {
        "customer_yaya_account": customer_yaya_account,
        "start_at": start_at,
        "bill_code": bill_code,
        "bill_season": bill_season,
        "cluster": cluster,
        "description": description,
        "phone": phone,
        "email": email,
        "details": details,
      }.items() if value is not None
    }
  }

  api_response = await api_request("POST", "/bill/update", "", payload, api_key)
  return api_response

async def bulk_bill_list(client_yaya_account, param: Optional[dict] = None, api_key: Optional[str] = None):
  page_number_param = param or {"p": 1}
  api_response = await api_request("POST", "/bill/list", page_number_param, {"client_yaya_account": client_yaya_account}, api_key)
  return api_response

async def bulk_bill_find(client_yaya_account, bill_id, api_key = None):
  api_response = await api_request("POST", "/bill/find", "", {"bill_id": bill_id, "client_yaya_account": client_yaya_account}, api_key)
  return api_response


async def get_utilities_list(api_key: Optional[str] = None):
    """
    Fetches the list of utilities.

    :param api_key: Optional API key for authentication.
    :return: API response.
    """
    api_response = await api_request("GET", "/utilities/list", "", None, api_key)
    return api_response

async def post_utilities_list(
    bill_id: str,
    client_yaya_account: str,
    api_key: Optional[str] = None
):
    """
    Posts a request to fetch utilities list based on bill ID and client Yaya account.

    :param bill_id: The ID of the bill.
    :param client_yaya_account: The Yaya account of the bill provider.
    :param api_key: Optional API key for authentication.
    :return: API response.
    """
    payload = {
        "bill_id": bill_id,
        "client_yaya_account": client_yaya_account
    }
    
    api_response = await api_request("POST", "/utilities/list", "", payload, api_key)
    return api_response



