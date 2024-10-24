from ..functions.api_request import api_request

from rest_framework import status

from django.http import StreamingHttpResponse

from ..serializers.user_serializers import CustomerUserSerializer, BusinessUserSerializer

import json

from typing import Optional

async def get_organization(api_key = None):
  api_response = await api_request("GET", "/user/organization", "", None, api_key)
  return api_response

async def get_profile(api_key = None):
  api_response = await api_request("GET", "/user/profile", "", None, api_key)
  return api_response

async def search_user(query: str, api_key: str = None):
  api_response = await api_request("POST", "/user/search", "", { "query": query }, api_key)
  return api_response

async def get_balance(api_key: str = None):
  api_response = await api_request("GET", "/user/balance", "", None, api_key)
  return api_response

async def create_customer_user(data, api_key = None):
  serializer = CustomerUserSerializer(data=data)

  if serializer.is_valid():
      validated_data = serializer.validated_data
      api_response = await api_request("POST", "/user/register", "", validated_data, api_key)
      return api_response
  else:
      errors = serializer.errors
      json_errors = json.dumps(errors)

      def error_generator():
          yield json_errors

      return StreamingHttpResponse(
        error_generator(),
        content_type='application/json',
        status=status.HTTP_400_BAD_REQUEST,
      )
  
async def create_business_user(data, api_key = None):
  serializer = BusinessUserSerializer(data=data)

  if serializer.is_valid():
      validated_data = serializer.validated_data
      api_response = await api_request("POST", "/user/register-business", "", validated_data, api_key)
      return api_response
  else:
      errors = serializer.errors
      json_errors = json.dumps(errors)

      def error_generator():
          yield json_errors

      return StreamingHttpResponse(
        error_generator(),
        content_type='application/json',
        status=status.HTTP_400_BAD_REQUEST,
      )
  
async def update_user(
      account_name: Optional[str] = None,
      name: Optional[str] = None,
      gender: Optional[str] = None, 
      region: Optional[str] = None, 
      location: Optional[str] = None, 
      date_of_birth: Optional[str] = None, 
      sms_notification_enable: Optional[bool] = None, 
      email_notification_enable: Optional[bool] = None, 
      app_notification_enable: Optional[bool] = None, 
      api_key: str = None
  ):
  payload = {
    **{
      key: value for key, value in {
        "account_name": account_name, 
        "name": name, 
        "gender": gender, 
        "region": region, 
        "location": location, 
        "date_of_birth": date_of_birth, 
        "sms_notification_enable": sms_notification_enable, 
        "email_notification_enable": email_notification_enable, 
        "app_notification_enable": app_notification_enable
      }.items() if value is not None
    }
  }
  api_response = await api_request("POST", "/user/update", "", payload, api_key)
  return api_response