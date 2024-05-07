from ..functions.api_request import api_request

async def create_equb(equb_account, title, description, location, latitude, longitude, period, amount, private):
  api_response = await api_request("POST", "/equb/create", "", { "equb_account": equb_account, "title": title,"description": description,"location": location,"latitude": latitude,"longitude": longitude,"period": period,"amount": amount,"private": private,})
  return api_response

async def update_equb(id, title, description, location, latitude, longitude, period, amount, private):
  api_response = await api_request("PUT", "/equb/update/" + id, {"title": title, "description": description, "location": location, "latitude": latitude, "longitude": longitude, "period": period,"amount": amount,"private": private,})
  return api_response

async def create_new_round_of_equb(id):
  api_response = await api_request("GET", "/equb/create-new-round/" + id, "")
  return api_response

async def equb_payments(id):
  api_response = await api_request("GET", "/equb/payments/" + id, "")
  return api_response

async def equb_rounds_by_id(id):
  api_response = await api_request("GET", "/equb/rounds/" + id, "")
  return api_response

async def equb_rounds_by_name(name):
  api_response = await api_request("GET", "/equb/rounds/by-name/" + name, "", None)
  return api_response

async def list_of_equbs():
  api_response = await api_request("GET", "/equb/public", "", None)
  return api_response

async def find_equbs_by_user():
  api_response = await api_request("GET", "/equb/find-by-user", "", None)
  return api_response

async def find_equb_by_id(id):
  api_response = await api_request("GET", "/equb/find/" + id, "")
  return api_response

async def find_equb_by_name(name):
  api_response = await api_request("GET", "/equb/find-by-name/" + name, "", None)
  return api_response

async def pay_equb_round(id, round, payment):
  api_response = await api_request("GET", "/equb/pay/" + id + "/" + round + "/" + payment, "", None)
  return api_response

async def find_members_of_equb(id):
  api_response = await api_request("GET", "/equb/" + id + "/members", "", None)
  return api_response

async def remove_members_of_equb(id):
  api_response = await api_request("GET", "/equb/remove-member/" + id, "")
  return api_response

async def join_equb(id):
  api_response = await api_request("GET", "/equb/" + id + "/join", "", None)
  return api_response

async def leave_equb(id):
  api_response = await api_request("GET", "/equb/" + id + "/leave", "", None)
  return api_response