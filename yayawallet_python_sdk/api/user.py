from ..functions.api_request import api_request

from rest_framework import status

from django.http import StreamingHttpResponse

from ..serializers.user_serializers import CustomerUserSerializer, BusinessUserSerializer

import json

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